/*
 * sc_speedtrap
 *
 * $Id: sc_speedtrap.c,v 1.18 2013/08/31 04:43:33 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2013 The Regents of the University of California
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef lint
static const char rcsid[] =
  "$Id: sc_speedtrap.c,v 1.18 2013/08/31 04:43:33 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_ADDRFILE    0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_STOP        0x0010
#define OPT_LOG         0x0020
#define OPT_UNIX        0x0040
#define OPT_SKIPFILE    0x0080
#define OPT_ALIASFILE   0x0100
#define OPT_DUMP        0x0200
#define OPT_INCR        0x0400
#define OPT_ALL         0xffff

typedef struct sc_targetipid sc_targetipid_t;

typedef struct sc_skippair
{
  scamper_addr_t   *a;
  scamper_addr_t   *b;
} sc_skippair_t;

typedef struct sc_target
{
  scamper_addr_t   *addr;
  splaytree_node_t *tree_node;
  heap_node_t      *heap_node;
  int               attempt;
  int               ptb;
  sc_targetipid_t  *last;
  slist_t          *samples;
  void             *data;
} sc_target_t;

struct sc_targetipid
{
  sc_target_t      *target;
  struct timeval    tx, rx;
  uint32_t          ipid;
};

typedef struct sc_targetset
{
  slist_t          *targets;
  slist_node_t     *next;
  struct timeval    min, max;
  slist_t          *blocked;
  dlist_node_t     *node;
  int               attempt;
  slist_node_t     *s1, *s2;
} sc_targetset_t;

typedef struct sc_wait
{
  struct timeval    tv;
  void             *data;
} sc_wait_t;

typedef struct sc_addr2ptr
{
  scamper_addr_t   *addr;
  void             *ptr;
} sc_addr2ptr_t;

typedef struct sc_dump
{
  char  *descr;
  int  (*proc_ping)(const scamper_ping_t *ping);
  int  (*proc_ally)(const scamper_dealias_t *dealias);
  void (*finish)(void);
} sc_dump_t;

/* declare dump functions used for dump_funcs[] below */
static int  process_1_ping(const scamper_ping_t *);
static int  process_1_ally(const scamper_dealias_t *);
static void finish_1(void);
static int  process_2_ping(const scamper_ping_t *);
static int  process_3_ping(const scamper_ping_t *);
static int  process_3_ally(const scamper_dealias_t *);
static void finish_3(void);

static uint32_t               options       = 0;
static char                  *addressfile   = NULL;
static unsigned int           port          = 0;
static char                  *unix_name     = NULL;
static splaytree_t           *targets       = NULL;
static slist_t               *probelist     = NULL;
static slist_t               *incr          = NULL;
static heap_t                *waiting       = NULL;
static splaytree_t           *skiptree      = NULL;
static char                  *skipfile      = NULL;
static int                    scamper_fd    = -1;
static char                  *readbuf       = NULL;
static size_t                 readbuf_len   = 0;
static char                  *outfile_name  = NULL;
static scamper_file_t        *outfile       = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static int                    data_left     = 0;
static int                    more          = 0;
static int                    probing       = 0;
static int                    mode          = 0;
static struct timeval         now;
static FILE                  *logfile       = NULL;
static FILE                  *aliasfile     = NULL;
static int                    fudge         = 65535;
static slist_t               *descend       = NULL;
static dlist_t               *overlap_act   = NULL;
static slist_t               *candidates    = NULL;
static const char            *step_names[] = {"classify","descend","overlap",
					      "descend2","candidates","ally"};
static int                    step_namec = sizeof(step_names)/sizeof(char *);
static char                  *stop_stepname = NULL;
static int                    stop_stepid   = 0;

static uint32_t              *pairwise_uint32 = NULL;
static int                    pairwise_uint32_max = 0;
static sc_targetipid_t      **pairwise_tipid = NULL;
static int                    pairwise_tipid_max = 0;

static int                    dump_id       = 0;
static int                    dump_stop     = 0;
static char                 **dump_files;
static int                    dump_filec    = 0;
static const sc_dump_t        dump_funcs[] = {
  {NULL, NULL, NULL, NULL},
  {"dump transitive closure",
   process_1_ping, process_1_ally, finish_1},
  {"dump interface classification",
   process_2_ping, NULL,           NULL},
  {"summary table of per-stage statistics",
   process_3_ping, process_3_ally, finish_3},
};
static int dump_funcc = sizeof(dump_funcs) / sizeof(sc_dump_t);

#define MODE_CLASSIFY   0
#define MODE_DESCEND    1
#define MODE_OVERLAP    2
#define MODE_DESCEND2   3
#define MODE_CANDIDATES 4
#define MODE_ALLY       5

static void usage(uint32_t opt_mask)
{
  int i;

  fprintf(stderr,
    "usage: sc_speedtrap [-a addressfile] [-o outfile] [-p port] [-U unix]\n"
    "                    [-I] [-A aliasfile] [-l log] [-s stop] [-S skipfile]\n"
    "\n"
    "       sc_speedtrap [-d dump] file1.warts .. fileN.warts\n"
    "\n");

  if(opt_mask == 0)
    fprintf(stderr, "       sc_speedtrap -?\n\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_speedtrap\n");

  if(opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "     -a input addressfile\n");

  if(opt_mask & OPT_DUMP)
    {
      fprintf(stderr, "     -d dump selection\n");
      for(i=1; i<dump_funcc; i++)
	  printf("        %2d : %s\n", i, dump_funcs[i].descr);
    }

  if(opt_mask & OPT_INCR)
    fprintf(stderr, "     -I input addresses increment, skip classify step\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");

  if(opt_mask & OPT_SKIPFILE)
    fprintf(stderr, "     -S input skipfile\n");

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "     -l output logfile\n");

  if(opt_mask & OPT_STOP)
    {
      fprintf(stderr,
	      "     -s step to halt on completion of\n"
	      "        [%s", step_names[0]);
      for(i=1; i<step_namec; i++)
	fprintf(stderr, "|%s", step_names[i]);
      fprintf(stderr, "]\n");
    }

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U unix domain to find scamper on\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  char hostname[255+1];
  long lo;
  char *opts = "?a:A:d:Il:o:p:s:S:U:w:";
  char *opt_port = NULL, *opt_unix = NULL, *opt_log = NULL;
  char *opt_aliasfile = NULL, *opt_dump = NULL;
  time_t tt;
  int i, ch;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRFILE;
	  addressfile = optarg;
	  break;

	case 'A':
	  options |= OPT_ALIASFILE;
	  opt_aliasfile = optarg;
	  break;

	case 'd':
	  options |= OPT_DUMP;
	  opt_dump = optarg;
	  break;

	case 'I':
	  options |= OPT_INCR;
	  break;

	case 'l':
	  options |= OPT_LOG;
	  opt_log = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 's':
	  options |= OPT_STOP;
	  stop_stepname = optarg;
	  break;

	case 'S':
	  options |= OPT_SKIPFILE;
	  skipfile = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  opt_unix = optarg;
	  break;

	case '?':
	default:
	  usage(OPT_ALL);
	  return -1;
	}
    }

  if((options & (OPT_ADDRFILE|OPT_OUTFILE|OPT_DUMP)) != (OPT_ADDRFILE|OPT_OUTFILE) &&
     (options & (OPT_ADDRFILE|OPT_OUTFILE|OPT_DUMP)) != OPT_DUMP)
    {
      usage(0);
      return -1;
    }

  if(options & (OPT_ADDRFILE|OPT_OUTFILE))
    {
      if((options & (OPT_PORT|OPT_UNIX)) == 0 ||
	 (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX) ||
	 argc - optind > 0)
	{
	  usage(OPT_ADDRFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX);
	  return -1;
	}

      if(options & OPT_PORT)
	{
	  if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	    {
	      usage(OPT_PORT);
	      return -1;
	    }
	  port = lo;
	}
      else if(options & OPT_UNIX)
	{
	  unix_name = opt_unix;
	}

      if(opt_aliasfile != NULL)
	{
	  if(gethostname(hostname, sizeof(hostname)) != 0)
	    {
	      usage(OPT_ALIASFILE);
	      fprintf(stderr, "could not gethostname\n");
	      return -1;
	    }
	  if((aliasfile = fopen(opt_aliasfile, "a")) == NULL)
	    {
	      usage(OPT_ALIASFILE);
	      fprintf(stderr, "could not open %s\n", opt_aliasfile);
	      return -1;
	    }
	  gettimeofday_wrap(&now);
	  tt = now.tv_sec;
	  fprintf(aliasfile, "# %s %s", hostname, asctime(localtime(&tt)));
	  fflush(aliasfile);
	}

      if(stop_stepname != NULL)
	{
	  for(i=0; i<step_namec; i++)
	    {
	      if(strcasecmp(stop_stepname, step_names[i]) == 0)
		{
		  stop_stepid = i;
		  break;
		}
	    }
	  if(i == step_namec)
	    {
	      usage(OPT_STOP);
	      return -1;
	    }
	}

      if(opt_log != NULL)
	{
	  if((logfile = fopen(opt_log, "w")) == NULL)
	    {
	      usage(OPT_LOG);
	      fprintf(stderr, "could not open %s\n", opt_log);
	      return -1;
	    }
	}
    }
  else
    {
      if(argc - optind < 1)
	{
	  usage(0);
	  return -1;
	}
      if(string_tolong(opt_dump, &lo) != 0 || lo < 1 || lo > dump_funcc)
	{
	  usage(OPT_DUMP);
	  return -1;
	}
      dump_id    = lo;
      dump_files = argv + optind;
      dump_filec = argc - optind;
    }

  return 0;
}

static int mode_ok(int m)
{
  if(stop_stepname == NULL)
    return 1;
  if(m > stop_stepid)
    return 0;
  return 1;
}

static int slist_count_cmp(const slist_t *a, const slist_t *b)
{
  int al = slist_count(a), bl = slist_count(b);
  if(al > bl) return -1;
  if(al < bl) return  1;
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int tree_to_slist(void *ptr, void *entry)
{
  slist_tail_push((slist_t *)ptr, entry);
  return 0;
}

static void hms(int x, int *h, int *m, int *s)
{
  *s = x % 60; x -= *s; x /= 60;
  *m = x % 60; x -= *m;
  *h = x / 60;
  return;
}

static void logprint(char *format, ...)
{
  va_list ap;
  char msg[131072];

  if(logfile != NULL)
    {
      va_start(ap, format);
      vsnprintf(msg, sizeof(msg), format, ap);
      va_end(ap);
      fprintf(logfile, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(logfile);
    }

  return;
}

static int uint32_cmp(const void *va, const void *vb)
{
  const uint32_t a = *((uint32_t *)va);
  const uint32_t b = *((uint32_t *)vb);
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int uint32_find(uint32_t *a, size_t len, uint32_t u32)
{
  if(bsearch(&u32, a, len, sizeof(uint32_t), uint32_cmp) != NULL)
    return 1;
  return 0;
}

static int ipid_inseq3(uint64_t a, uint64_t b, uint64_t c)
{
  if(a == b || b == c || a == c)
    return 0;
  if(a > b)
    b += 0x100000000ULL;
  if(a > c)
    c += 0x100000000ULL;

  if(fudge != 0)
    {
      if(b - a > fudge || c - b > fudge)
	return 0;
    }
  else
    {
      if(a > b || b > c)
	return 0;
    }
  return 1;
}

static int ipid_incr(uint32_t *ipids, int ipidc)
{
  int i;
  if(ipidc < 3)
    return 0;
  for(i=2; i<ipidc; i++)
    if(ipid_inseq3(ipids[i-2], ipids[i-1], ipids[i]) == 0)
      return 0;
  return 1;
}

static void sc_addr2ptr_free(sc_addr2ptr_t *a2p)
{
  if(a2p == NULL)
    return;
  if(a2p->addr != NULL) scamper_addr_free(a2p->addr);
  free(a2p);
  return;
}

static sc_addr2ptr_t *sc_addr2ptr_find(splaytree_t *tree, scamper_addr_t *addr)
{
  sc_addr2ptr_t fm; fm.addr = addr;
  return splaytree_find(tree, &fm);
}

static int sc_addr2ptr_add(splaytree_t *tree, scamper_addr_t *addr, void *ptr)
{
  sc_addr2ptr_t *a2p;
  if((a2p = malloc_zero(sizeof(sc_addr2ptr_t))) == NULL)
    return -1;
  a2p->addr = scamper_addr_use(addr);
  a2p->ptr  = ptr;
  if(splaytree_insert(tree, a2p) == NULL)
    return -1;
  return 0;
}

static int sc_addr2ptr_cmp(const sc_addr2ptr_t *a, const sc_addr2ptr_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static int ping_read(const scamper_ping_t *ping, uint32_t *ipids,
		     int *ipidc, int *replyc)
{
  scamper_ping_reply_t *reply;
  int i, maxipidc = *ipidc;

  *ipidc = 0;
  *replyc = 0;

  for(i=0; i<ping->ping_sent; i++)
    {
      if((reply = ping->ping_replies[i]) == NULL)
	continue;
      if(SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) == 0)
	continue;
      (*replyc)++;
      if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
	{
	  if(*ipidc == maxipidc)
	    return -1;
	  ipids[*ipidc] = reply->reply_ipid32;
	  (*ipidc)++;
	}
    }

  return 0;
}

static splaytree_t *d1_tree = NULL;

static int process_1_ping(const scamper_ping_t *ping)
{
  uint32_t ipids[10];
  slist_t *list = NULL;
  scamper_addr_t *addr;
  int ipidc, replyc;

  if(ping->userid != 0)
    return 0;

  ipidc = sizeof(ipids) / sizeof(uint32_t);
  if(ping_read(ping, ipids, &ipidc, &replyc) != 0)
    return -1;
  if(ipid_incr(ipids, ipidc) == 0)
    return 0;

  if(d1_tree == NULL &&
     (d1_tree = splaytree_alloc((splaytree_cmp_t)sc_addr2ptr_cmp)) == NULL)
    return -1;

  if(sc_addr2ptr_find(d1_tree, ping->dst) != NULL)
    return 0;

  if((list = slist_alloc()) == NULL ||
     slist_tail_push(list, scamper_addr_use(ping->dst)) == NULL ||
     sc_addr2ptr_add(d1_tree, ping->dst, list) != 0)
    goto err;

  return 0;

 err:
  if(list != NULL)
    {
      while((addr = slist_head_pop(list)) == NULL)
	scamper_addr_free(addr);
      slist_free(list);
    }
  return -1;
}

static int process_1_ally(const scamper_dealias_t *dealias)
{
  const scamper_dealias_ally_t *ally = dealias->data;
  sc_addr2ptr_t *a2p_a, *a2p_b, *a2p_x;
  slist_t *list_a, *list_b, *list_x;
  scamper_addr_t *a = ally->probedefs[0].dst;
  scamper_addr_t *b = ally->probedefs[1].dst;
  scamper_addr_t *x;

  if(dealias->result != SCAMPER_DEALIAS_RESULT_ALIASES)
    return 0;

  a2p_a = sc_addr2ptr_find(d1_tree, a);
  a2p_b = sc_addr2ptr_find(d1_tree, b);

  if(a2p_a != NULL && a2p_b != NULL)
    {
      list_a = a2p_a->ptr; list_b = a2p_b->ptr;
      if(list_a == list_b)
	return 0;
      while((x = slist_head_pop(list_b)) != NULL)
	{
	  if(slist_tail_push(list_a, x) == NULL)
	    goto err;
	  a2p_x = sc_addr2ptr_find(d1_tree, x);
	  a2p_x->ptr = list_a;
	}
      slist_free(list_b);
    }
  else if(a2p_a != NULL)
    {
      list_a = a2p_a->ptr;
      if(slist_tail_push(list_a, scamper_addr_use(b)) == NULL ||
	 sc_addr2ptr_add(d1_tree, b, list_a) != 0)
	goto err;
    }
  else if(a2p_b != NULL)
    {
      list_b = a2p_b->ptr;
      if(slist_tail_push(list_b, scamper_addr_use(a)) == NULL ||
	 sc_addr2ptr_add(d1_tree, a, list_b) != 0)
	goto err;
    }
  else
    {
      if((list_x = slist_alloc()) == NULL ||
	 slist_tail_push(list_x, scamper_addr_use(a)) == NULL ||
	 slist_tail_push(list_x, scamper_addr_use(b)) == NULL ||
	 sc_addr2ptr_add(d1_tree, a, list_x) != 0 ||
	 sc_addr2ptr_add(d1_tree, b, list_x) != 0)
	goto err;
    }

  return 0;

 err:
  return -1;
}

static void finish_1(void)
{
  scamper_addr_t *addr;
  sc_addr2ptr_t *a2p;
  slist_t *a2ps = NULL;
  slist_t *sets = NULL;
  slist_t *addrs = NULL;
  slist_t *last;
  char buf[128];
  int x;

  if((a2ps = slist_alloc()) == NULL || (sets = slist_alloc()) == NULL)
    return;
  splaytree_inorder(d1_tree, tree_to_slist, a2ps);
  splaytree_free(d1_tree, NULL);

  while((a2p = slist_head_pop(a2ps)) != NULL)
    {
      slist_tail_push(sets, a2p->ptr);
      a2p->ptr = NULL; sc_addr2ptr_free(a2p);
    }
  slist_free(a2ps);

  last = NULL;
  slist_qsort(sets, (slist_cmp_t)slist_count_cmp);
  while((addrs = slist_head_pop(sets)) != NULL)
    {
      if(last == addrs)
	continue;
      slist_qsort(addrs, (slist_cmp_t)scamper_addr_human_cmp);
      x = 0;
      while((addr = slist_head_pop(addrs)) != NULL)
	{
	  if(x != 0) printf(" ");
	  printf("%s", scamper_addr_tostr(addr, buf, sizeof(buf)));
	  scamper_addr_free(addr);
	  x++;
	}
      printf("\n");
      slist_free(addrs);
      last = addrs;
    }
  slist_free(sets);
  return;
}

static int process_2_ping(const scamper_ping_t *ping)
{
  uint32_t ipids[10];
  int ipidc, replyc;
  char buf[64];

  if(ping->userid != 0)
    {
      dump_stop = 1;
      return 0;
    }

  ipidc = sizeof(ipids) / sizeof(uint32_t);
  if(ping_read(ping, ipids, &ipidc, &replyc) != 0)
    return -1;

  scamper_addr_tostr(ping->dst, buf, sizeof(buf));
  if(ipidc == 0)
    {
      if(replyc == 0)
	printf("%s unresponsive\n", buf);
      else if(replyc == 1)
	printf("%s gone-silent\n", buf);
      else
	printf("%s no-frags\n", buf);
    }
  else if(ipidc < 3)
    printf("%s insuff-ipids\n", buf);
  else if(ipid_incr(ipids, ipidc) == 0)
    printf("%s random\n", buf);
  else
    printf("%s incr\n", buf);

  return 0;
}

static int            d3_states_probec[6];
static struct timeval d3_states_first[6];
static struct timeval d3_states_last[6];

static int process_3_ping(const scamper_ping_t *ping)
{
  uint32_t id = ping->userid;
  if(timeval_cmp(&d3_states_first[id], &ping->start) > 0 ||
     d3_states_first[id].tv_sec == 0)
    timeval_cpy(&d3_states_first[id], &ping->start);
  if(timeval_cmp(&d3_states_last[id], &ping->start) < 0)
    timeval_cpy(&d3_states_last[id], &ping->start);
  d3_states_probec[id] += ping->ping_sent;
  return 0;
}

static int process_3_ally(const scamper_dealias_t *dealias)
{
  uint32_t id = 5;
  d3_states_probec[id] += dealias->probec;
  if(timeval_cmp(&d3_states_first[id], &dealias->start) > 0 ||
     d3_states_first[id].tv_sec == 0)
    timeval_cpy(&d3_states_first[id], &dealias->start);
  if(timeval_cmp(&d3_states_last[id], &dealias->start) < 0)
    timeval_cpy(&d3_states_last[id], &dealias->start);
  return 0;
}

static void finish_3(void)
{
  int h, m, s, i, sum_time = 0, sum_probes = 0;
  struct timeval tv;

  for(i=0; i<6; i++)
    {
      timeval_diff_tv(&tv, &d3_states_first[i], &d3_states_last[i]);
      hms(tv.tv_sec, &h, &m, &s);
      assert((h * 3600) + (m * 60) + s == tv.tv_sec);
      printf("%d: %d %d:%02d:%02d\n", i, d3_states_probec[i], h, m, s);
      sum_time += tv.tv_sec; 
      sum_probes += d3_states_probec[i];
    }
  hms(sum_time, &h, &m, &s);
  printf("total: %d %d:%02d:%02d\n", sum_probes, h, m, s);

  return;
}

static int sc_wait(struct timeval *tv, void *data)
{
  sc_wait_t *w;
  if((w = malloc_zero(sizeof(sc_wait_t))) == NULL)
    return -1;
  timeval_cpy(&w->tv, tv);
  w->data = data;
  if(heap_insert(waiting, w) == NULL)
    return -1;
  return 0;
}

static void sc_target_set(sc_target_t *tg, int ptb, int attempt, void *data)
{
  tg->ptb = ptb;
  tg->attempt = attempt;
  tg->data = data;
  return;
}

static int sc_wait_cmp(const void *a, const void *b)
{
  return timeval_cmp(&((sc_wait_t *)b)->tv, &((sc_wait_t *)a)->tv);
}

static int sc_target_addr_cmp(const sc_target_t *a, const sc_target_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static int sc_target_ipid_cmp(const sc_target_t *a, const sc_target_t *b)
{
  assert(a->last != NULL); assert(b->last != NULL);
  if(a->last->ipid > b->last->ipid) return -1;
  if(a->last->ipid < b->last->ipid) return  1;
  return 0;
}

static sc_target_t *sc_target_findtree(scamper_addr_t *addr)
{
  sc_target_t fm;
  fm.addr = addr;
  return splaytree_find(targets, &fm);
}

static void sc_target_detachtree(sc_target_t *tg)
{
  if(tg->tree_node != NULL)
    {
      splaytree_remove_node(targets, tg->tree_node);
      tg->tree_node = NULL;
    }
  return;
}

static sc_targetipid_t *sc_target_sample(sc_target_t *tg, sc_targetipid_t *x)
{
  sc_targetipid_t *ti;
  if((ti = memdup(x, sizeof(sc_targetipid_t))) == NULL)
    return NULL;
  ti->target = tg;
  if(slist_tail_push(tg->samples, ti) == NULL)
    {
      free(ti);
      return NULL;
    }
  tg->last = ti;
  return ti;
}

static sc_target_t *sc_target_free(sc_target_t *tg)
{
  sc_targetipid_t *ti;

  if(tg == NULL)
    return NULL;

  if(tg->samples != NULL)
    {
      while((ti = slist_head_pop(tg->samples)) != NULL)
	free(ti);
      slist_free(tg->samples);
    }

  if(tg->tree_node != NULL)
    splaytree_remove_node(targets, tg->tree_node);
  if(tg->heap_node != NULL)
    heap_delete(waiting, tg->heap_node);
  if(tg->addr != NULL)
    scamper_addr_free(tg->addr);

  free(tg);
  return NULL;
}

static int sc_target_new(char *addr, void *param)
{
  sc_target_t *target = NULL;
  scamper_addr_t *a;

  if(addr[0] == '#' || addr[0] == '\0')
    return 0;

  if((a = scamper_addr_resolve(AF_INET6, addr)) == NULL)
    {
      fprintf(stderr, "could not resolve '%s'\n", addr);
      goto err;
    }

  /* in 2000::/3 */
  if(scamper_addr_isunicast(a) != 1)
    {
      scamper_addr_free(a);
      return 0;
    }

  if((target = malloc_zero(sizeof(sc_target_t))) == NULL ||
     (target->samples = slist_alloc()) == NULL)
    goto err;
  target->addr = a; a = NULL;

  if(slist_tail_push(probelist, target) == NULL ||
     ((options & OPT_INCR) && slist_tail_push(incr, target) == NULL))
    {
      fprintf(stderr, "could push '%s'\n", addr);
      goto err;
    }

  return 0;

 err:
  if(a != NULL) scamper_addr_free(a);
  if(target != NULL)
    {
      if(target->addr != NULL) scamper_addr_free(target->addr);
      free(target);
    }
  return -1;
}

static int sc_skippair_cmp(const sc_skippair_t *a, const sc_skippair_t *b)
{
  int rc;
  if((rc = scamper_addr_cmp(a->a, b->a)) != 0)
    return rc;
  return scamper_addr_cmp(a->b, b->b);
}

static int sc_skippair_test(scamper_addr_t *a, scamper_addr_t *b)
{
  sc_skippair_t fm;
  if(scamper_addr_cmp(a, b) < 0) {
    fm.a = a; fm.b = b;
  } else {
    fm.a = b; fm.b = a;
  }
  if(splaytree_find(skiptree, &fm) == NULL)
    return 0;
  return 1;
}

static void sc_skippair_free(sc_skippair_t *pair)
{
  if(pair == NULL)
    return;
  if(pair->a != NULL) scamper_addr_free(pair->a);
  if(pair->b != NULL) scamper_addr_free(pair->b);
  free(pair);
  return;
}

static int sc_skippair_add(scamper_addr_t *a, scamper_addr_t *b)
{
  sc_skippair_t *pair = NULL;
  if((pair = malloc_zero(sizeof(sc_skippair_t))) == NULL)
    return -1;
  if(scamper_addr_cmp(a, b) < 0)
    {
      pair->a = scamper_addr_use(a);
      pair->b = scamper_addr_use(b);
    }
  else
    {
      pair->a = scamper_addr_use(b);
      pair->b = scamper_addr_use(a);
    }
  if(splaytree_insert(skiptree, pair) == NULL)
    {
      sc_skippair_free(pair);
      return -1;
    }
  return 0;
}

static int sc_skippair_new(char *line, void *param)
{
  scamper_addr_t *a = NULL, *b = NULL;
  char *astr, *bstr, *ptr;

  if(line[0] == '#' || line[0] == '\0')
    return 0;
  astr = ptr = line;
  while(*ptr != '\0' && isspace(*ptr) == 0)
    ptr++;
  if(*ptr == '\0')
    goto err;
  *ptr = '\0'; ptr++;
  while(isspace(*ptr) != 0)
    ptr++;
  bstr = ptr;
  while(*ptr != '\0' && isspace(*ptr) == 0)
    ptr++;
  *ptr = '\0';

  if((a = scamper_addr_resolve(AF_INET6, astr)) == NULL)
    {
      fprintf(stderr, "could not resolve '%s'\n", astr);
      goto err;
    }
  if((b = scamper_addr_resolve(AF_INET6, bstr)) == NULL)
    {
      fprintf(stderr, "could not resolve '%s'\n", bstr);
      goto err;
    }
  if(sc_skippair_test(a, b) == 0 && sc_skippair_add(a, b) != 0)
    goto err;

  scamper_addr_free(a);
  scamper_addr_free(b);
  return 0;

 err:
  if(a != NULL) scamper_addr_free(a);
  if(b != NULL) scamper_addr_free(b);
  return -1;
}

static int sc_targetipid_tx_cmp(const sc_targetipid_t *a,
				const sc_targetipid_t *b)
{
  return timeval_cmp(&a->tx, &b->tx);
}

static void sc_targetset_print(const sc_targetset_t *ts)
{
  sc_target_t *tg;
  slist_node_t *ss;
  size_t off = 0;
  char a[64], buf[131072];
  string_concat(buf, sizeof(buf), &off, "%p:", ts);
  for(ss=slist_head_node(ts->targets); ss != NULL; ss=slist_node_next(ss))
    {
      tg = slist_node_item(ss);
      string_concat(buf, sizeof(buf), &off, " %s",
		    scamper_addr_tostr(tg->addr, a, sizeof(a)));
    }
  logprint("%s\n", buf);
  return;
}

static int sc_targetset_targetcount_cmp(const sc_targetset_t *a,
					const sc_targetset_t *b)
{
  int ac = slist_count(a->targets);
  int bc = slist_count(b->targets);
  if(ac > bc) return -1;
  if(ac < bc) return  1;
  return 0;
}

static int sc_targetset_min_cmp(const sc_targetset_t *a,
				const sc_targetset_t *b)
{
  return timeval_cmp(&a->min, &b->min);
}

static void sc_targetset_free(sc_targetset_t *ts)
{
  if(ts == NULL)
    return;
  if(ts->targets != NULL) slist_free(ts->targets);
  if(ts->blocked != NULL) slist_free(ts->blocked);
  free(ts);
  return;
}

static sc_targetset_t *sc_targetset_alloc(void)
{
  sc_targetset_t *ts;
  if((ts = malloc_zero(sizeof(sc_targetset_t))) == NULL ||
     (ts->targets = slist_alloc()) == NULL ||
     (ts->blocked = slist_alloc()) == NULL)
    {
      sc_targetset_free(ts);
      return NULL;
    }
  return ts;
}

static int sample_overlap(const sc_targetipid_t *a, const sc_targetipid_t *b)
{
  int rc = timeval_cmp(&a->tx, &b->tx);
  if(rc < 0)
    {
      if(timeval_cmp(&a->rx, &b->tx) <= 0)
	return 0;
    }
  else if(rc > 0)
    {
      if(timeval_cmp(&b->rx, &a->tx) <= 0)
	return 0;
    }
  return 1;
}

static int pairwise_test(sc_targetipid_t **tis, int tc)
{
  sc_targetipid_t *ti, *st[2][2];
  sc_target_t *x = tis[0]->target;
  int si, sj, ipidc = 0;
  int i, rc = 0;

  st[0][0] = NULL; st[0][1] = NULL;
  st[1][0] = NULL; st[1][1] = NULL;

  if(tc > pairwise_uint32_max)
    {
      if(realloc_wrap((void **)&pairwise_uint32, tc * sizeof(uint32_t)) != 0)
	return -1;
      pairwise_uint32_max = tc;
    }

  for(i=0; i<tc; i++)
    {
      /* first, check if this IPID has already been observed */
      ti = tis[i];
      if(uint32_find(pairwise_uint32, ipidc, ti->ipid) != 0)
	return 0;
      pairwise_uint32[ipidc++] = ti->ipid;
      qsort(pairwise_uint32, ipidc, sizeof(uint32_t), uint32_cmp);

      if(ti->target == x) { si = 0; sj = 1; }
      else                { si = 1; sj = 0; }

      if(st[si][1] == NULL || st[sj][1] == NULL)
	goto next;

      if(timeval_cmp(&st[si][1]->tx, &st[sj][1]->tx) > 0)
	{
	  if(ipid_inseq3(st[sj][1]->ipid, st[si][1]->ipid, ti->ipid) == 0 &&
	     sample_overlap(st[sj][1], st[si][1]) == 0 &&
	     sample_overlap(st[si][1], ti) == 0)
	    return 0;
	  goto next;
	}

      if(sample_overlap(st[si][1], st[sj][1]) || sample_overlap(st[sj][1], ti))
	{
	  if(sample_overlap(st[sj][1], ti) && st[sj][0] != NULL &&
	     timeval_cmp(&st[si][1]->tx, &st[sj][0]->tx) < 0 &&
	     sample_overlap(st[si][1], st[sj][0]) == 0 &&
	     ipid_inseq3(st[si][1]->ipid, st[sj][0]->ipid, ti->ipid) == 0)
	    return 0;
	  goto next;
	}

      if(ipid_inseq3(st[si][1]->ipid, st[sj][1]->ipid, ti->ipid) == 1)
	rc = 1;
      else
	return 0;

    next:
      st[si][0] = st[si][1];
      st[si][1] = ti;
    }

  return rc;
}

static int pairwise(sc_target_t *ta, sc_target_t *tb)
{
  slist_node_t *ss;
  size_t len;
  int tc;

  tc = slist_count(ta->samples) + slist_count(tb->samples);
  if(tc > pairwise_tipid_max)
    {
      len = tc * sizeof(sc_targetipid_t *);
      if(realloc_wrap((void **)&pairwise_tipid, len) != 0)
	return -1;
      pairwise_tipid_max = tc;
    }

  tc = 0;
  for(ss=slist_head_node(ta->samples); ss!=NULL; ss=slist_node_next(ss))
    pairwise_tipid[tc++] = slist_node_item(ss);
  for(ss=slist_head_node(tb->samples); ss!=NULL; ss=slist_node_next(ss))
    pairwise_tipid[tc++] = slist_node_item(ss);
  array_qsort((void **)pairwise_tipid, tc, (array_cmp_t)sc_targetipid_tx_cmp);

  return pairwise_test(pairwise_tipid, tc);
}

static int pairwise_all(slist_t *targets, slist_t *sets)
{
  slist_node_t *sa, *sb;
  sc_target_t *ta, *tb, *tg;
  sc_targetipid_t **tis = NULL;
  sc_targetset_t *ts, *tsa, *tsb;
  sc_addr2ptr_t *a2ts, *a2ts_a, *a2ts_b;
  splaytree_t *tree;
  dlist_t *list;
  char a[64], b[64];

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_addr2ptr_cmp)) == NULL ||
     (list = dlist_alloc()) == NULL)
    goto err;

  for(sa=slist_head_node(targets); sa != NULL; sa=slist_node_next(sa))
    {
      ta = slist_node_item(sa);
      if(slist_count(ta->samples) == 0)
	continue;

      for(sb=slist_node_next(sa); sb != NULL; sb=slist_node_next(sb))
	{
	  tb = slist_node_item(sb);
	  if(slist_count(tb->samples) == 0)
	    continue;
	  if(pairwise(ta, tb) != 1)
	    continue;

	  logprint("likely aliases: %s %s\n",
		   scamper_addr_tostr(ta->addr, a, sizeof(a)),
		   scamper_addr_tostr(tb->addr, b, sizeof(b)));
	  a2ts_a = sc_addr2ptr_find(tree, ta->addr);
	  a2ts_b = sc_addr2ptr_find(tree, tb->addr);

	  if(a2ts_a != NULL && a2ts_b != NULL)
	    {
	      tsa = a2ts_a->ptr; tsb = a2ts_b->ptr;
	      if(tsa == tsb)
		continue;
	      while((tg = slist_head_pop(tsb->targets)) != NULL)
		{
		  if(slist_tail_push(tsa->targets, tg) == NULL)
		    goto err;
		  a2ts = sc_addr2ptr_find(tree, tg->addr);
		  a2ts->ptr = tsa;
		}
	      dlist_node_pop(list, tsb->node);
	      sc_targetset_free(tsb);
	    }
	  else if(a2ts_a != NULL)
	    {
	      ts = a2ts_a->ptr;
	      if(slist_tail_push(ts->targets, tb) == NULL ||
		 sc_addr2ptr_add(tree, tb->addr, ts) != 0)
		goto err;
	    }
	  else if(a2ts_b != NULL)
	    {
	      ts = a2ts_b->ptr;
	      if(slist_tail_push(ts->targets, ta) == NULL ||
		 sc_addr2ptr_add(tree, ta->addr, ts) != 0)
		goto err;
	    }
	  else
	    {
	      if((ts = sc_targetset_alloc()) == NULL ||
		 (ts->node = dlist_tail_push(list, ts)) == NULL ||
		 slist_tail_push(ts->targets, ta) == NULL ||
		 slist_tail_push(ts->targets, tb) == NULL ||
		 sc_addr2ptr_add(tree, ta->addr, ts) != 0 ||
		 sc_addr2ptr_add(tree, tb->addr, ts) != 0)
		goto err;
	    }
	}
    }

  if(tree != NULL)
    {
      splaytree_free(tree, (splaytree_free_t)sc_addr2ptr_free);
      tree = NULL;
    }
  if(tis != NULL)
    {
      free(tis);
      tis = NULL;
    }
  while((ts = dlist_head_pop(list)) != NULL)
    {
      sc_targetset_print(ts);
      if(slist_tail_push(sets, ts) == NULL)
	goto err;
    }
  dlist_free(list);
  return 0;

 err:
  if(tree != NULL) splaytree_free(tree, free);
  if(list != NULL) dlist_free(list);
  if(tis != NULL) free(tis);
  return -1;
}

static void overlap_dump(void)
{
  sc_targetset_t *ts;
  sc_targetipid_t *ti;
  sc_target_t *tg;
  slist_node_t *sn, *so;
  char buf[64];

  for(sn=slist_head_node(probelist); sn != NULL; sn=slist_node_next(sn))
    {
      ts = slist_node_item(sn);
      logprint("# set %p %d.%06d %d.%06d\n", ts,
	       ts->min.tv_sec, (int)ts->min.tv_usec,
	       ts->max.tv_sec, (int)ts->max.tv_usec);
      for(so=slist_head_node(ts->targets); so != NULL; so=slist_node_next(so))
	{
	  tg = slist_node_item(so);
	  ti = slist_node_item(slist_tail_node(tg->samples));
	  logprint("%d.%06d %d.%06d %s %08x\n",
		   ti->tx.tv_sec, (int)ti->tx.tv_usec,
		   ti->rx.tv_sec, (int)ti->rx.tv_usec,
		   scamper_addr_tostr(tg->addr, buf, sizeof(buf)),
		   ti->ipid);
	}
    }
  return;
}

static void sc_targetset_nextpair(sc_targetset_t *ts)
{
  sc_target_t *t1, *t2;

  for(;;)
    {
      if(ts->s1 == NULL)
	{
	  ts->s1 = slist_head_node(ts->targets);
	  ts->s2 = slist_node_next(ts->s1);
	}
      else
	{
	  if((ts->s2 = slist_node_next(ts->s2)) == NULL)
	    {
	      if((ts->s1 = slist_node_next(ts->s1)) == NULL ||
		 (ts->s2 = slist_node_next(ts->s1)) == NULL)
		{
		  ts->s1 = ts->s2 = NULL;
		}
	    }
	}

      if(ts->s1 == NULL)
	break;

      t1 = slist_node_item(ts->s1);
      t2 = slist_node_item(ts->s2);
      if(sc_skippair_test(t1->addr, t2->addr) != 0)
	continue;
      if(pairwise(t1, t2) == 1)
	break;
    }

  ts->attempt = 0;
  return;
}

static int do_addressfile(void)
{
  return file_lines(addressfile, sc_target_new, NULL);
}

static int do_skipfile(void)
{
  if(skipfile == NULL)
    return 0;
  return file_lines(skipfile, sc_skippair_new, NULL);
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
  struct sockaddr_un sun;
  struct sockaddr_in sin;
  struct in_addr in;

  if(options & OPT_PORT)
    {
      inet_aton("127.0.0.1", &in);
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, port);
      if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  fprintf(stderr, "could not allocate new socket\n");
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
	  fprintf(stderr, "could not connect to scamper process\n");
	  return -1;
	}
      return 0;
    }
  else if(options & OPT_UNIX)
    {
      if(sockaddr_compose_un((struct sockaddr *)&sun, unix_name) != 0)
	{
	  fprintf(stderr, "could not build sockaddr_un\n");
	  return -1;
	}
      if((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
	  fprintf(stderr, "could not allocate unix domain socket\n");
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sun, sizeof(sun)) != 0)
	{
	  fprintf(stderr, "could not connect to scamper process\n");
	  return -1;
	}
      return 0;
    }

  return -1;
}

static int do_files(void)
{
  int pair[2];

  if((outfile = scamper_file_open(outfile_name, 'w', "warts")) == NULL)
    return -1;

  /*
   * setup a socketpair that is used to decode warts from a binary input.
   * pair[0] is used to write to the file, while pair[1] is used by
   * the scamper_file_t routines to parse the warts data.
   */
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    return -1;

  decode_in_fd  = pair[0];
  decode_out_fd = pair[1];
  decode_in = scamper_file_openfd(decode_in_fd, NULL, 'r', "warts");
  if(decode_in == NULL)
    return -1;

  if(fcntl_set(decode_in_fd, O_NONBLOCK) == -1)
    return -1;

  return 0;
}

static int test_ping6(sc_target_t *target, char *cmd, size_t len)
{
  size_t off = 0;
  char buf[64];
  string_concat(cmd, len, &off,
		"ping -O dl -U %d -c 6 -s 1300 -M 1280 %s\n",
		mode, scamper_addr_tostr(target->addr, buf, sizeof(buf)));
  return off;
}

static int test_ping1(sc_target_t *target, char *cmd, size_t len)
{
  size_t off = 0;
  char buf[64];

  string_concat(cmd, len, &off, "ping -O dl -U %d -c 2 -s 1300 -M 1280", mode);
  if(target->attempt == 0)
    string_concat(cmd, len, &off, " -o 1");
  string_concat(cmd, len, &off, " %s\n",
		scamper_addr_tostr(target->addr, buf, sizeof(buf)));

  return off;
}

static sc_target_t *target_classify(void)
{
  return slist_head_pop(probelist);
}

static sc_target_t *target_descend(void)
{
  return slist_head_pop(probelist);
}

static sc_target_t *target_overlap(void)
{
  sc_targetset_t *ts, *tt;
  sc_target_t *tg;
  dlist_node_t *dn;
  slist_node_t *sn;

  for(;;)
    {
      if((ts = slist_head_pop(probelist)) == NULL)
	return NULL;
      for(dn=dlist_head_node(overlap_act); dn != NULL; dn=dlist_node_next(dn))
	{
	  tt = dlist_node_item(dn);
	  if(timeval_cmp(&ts->min, &tt->max) < 0)
	    break;
	}
      if(dn == NULL)
	break;
      if(slist_tail_push(tt->blocked, ts) == NULL)
	return NULL;
    }

  if((ts->node = dlist_tail_push(overlap_act, ts)) == NULL)
    return NULL;

  slist_qsort(ts->targets, (slist_cmp_t)sc_target_ipid_cmp);
  sn = slist_head_node(ts->targets);
  tg = slist_node_item(sn);
  sc_target_set(tg, 0, 0, ts);
  ts->next = slist_node_next(sn);

  return tg;
}

static sc_target_t *target_descend2(void)
{
  return slist_head_pop(probelist);
}

static sc_target_t *target_candidates(void)
{
  sc_targetset_t *ts;
  sc_target_t *tg;
  if((ts = slist_head_pop(probelist)) == NULL)
    return NULL;
  slist_qsort(ts->targets, (slist_cmp_t)sc_target_ipid_cmp);
  ts->s1 = slist_head_node(ts->targets);
  ts->s2 = NULL;
  tg = slist_node_item(ts->s1);
  sc_target_set(tg, 0, 0, ts);
  return tg;
}

static sc_targetset_t *targetset_ally(void)
{
  sc_targetset_t *ts;
  for(;;)
    {
      if((ts = slist_head_pop(probelist)) == NULL)
	break;
      sc_targetset_nextpair(ts);
      if(ts->s1 != NULL)
	return ts;
      sc_targetset_free(ts);
    }
  return NULL;
}

static int do_method_ping(void)
{
  static int (*const test_func[])(sc_target_t *, char *, size_t) = {
    test_ping6,
    test_ping1,
    test_ping1,
    test_ping1,
    test_ping1,
  };
  static sc_target_t * (*const target_func[])(void) = {
    target_classify,
    target_descend,
    target_overlap,
    target_descend2,
    target_candidates,
  };

  sc_target_t *tg;
  sc_wait_t *w;
  char buf[128];
  size_t off;

  if((w = heap_head_item(waiting)) != NULL && timeval_cmp(&now, &w->tv) >= 0)
    {
      heap_remove(waiting);
      tg = w->data;
      free(w);
    }
  else if((tg = target_func[mode]()) == NULL)
    return 0;

  if((tg->tree_node = splaytree_insert(targets, tg)) == NULL)
    {
      fprintf(stderr, "could not add %s to tree\n",
	      scamper_addr_tostr(tg->addr, buf, sizeof(buf)));
      return -1;
    }

  if((off = test_func[mode](tg, buf, sizeof(buf))) == -1)
    {
      fprintf(stderr, "something went wrong\n");
      return -1;
    }

  write_wrap(scamper_fd, buf, NULL, off);
  probing++;
  more--;

  logprint("p %d, w %d, l %d : %s", probing, heap_count(waiting),
	   slist_count(probelist), buf);
  return 0;
}

static int do_method_ally(void)
{
  sc_targetset_t *ts;
  sc_target_t *tg;
  sc_wait_t *w;
  char cmd[192], addr[64];
  size_t off = 0;

  if((w = heap_head_item(waiting)) != NULL && timeval_cmp(&now, &w->tv) >= 0)
    {
      heap_remove(waiting);
      ts = w->data;
      free(w);
    }
  else if((ts = targetset_ally()) == NULL)
    return 0;

  tg = slist_node_item(ts->s1);
  if((tg->tree_node = splaytree_insert(targets, tg)) == NULL)
    {
      fprintf(stderr, "could not add %s to tree\n",
	      scamper_addr_tostr(tg->addr, addr, sizeof(addr)));
      return -1;
    }
  sc_target_set(tg, 0, 0, ts);

  string_concat(cmd, sizeof(cmd), &off,
		"dealias -U %d -m ally -W 1000 -p '%s' %s",
		mode, "-P icmp-echo -s 1300 -M 1280",
		scamper_addr_tostr(tg->addr, addr, sizeof(addr)));
  tg = slist_node_item(ts->s2);
  string_concat(cmd, sizeof(cmd), &off, " %s\n",
		scamper_addr_tostr(tg->addr, addr, sizeof(addr)));

  write_wrap(scamper_fd, cmd, NULL, off);
  probing++;
  more--;

  logprint("p %d, w %d, l %d : %s", probing, heap_count(waiting),
	   slist_count(probelist), cmd);
  return 0;
}

static int do_method(void)
{
  int rc;
  if(more < 1)
    return 0;
  if(mode != MODE_ALLY)
    rc = do_method_ping();
  else
    rc = do_method_ally();
  return rc;
}

static int reply_classify(sc_target_t *target, sc_targetipid_t *p,
			  uint16_t ipidc, uint16_t rxd)
{
  slist_node_t *sn;
  char addr[64];
  uint16_t u16;

  scamper_addr_tostr(target->addr, addr, sizeof(addr));

  if(rxd == 0)
    {
      logprint("%s unresponsive\n", addr);
      sc_target_free(target);
      goto done;
    }

  if(ipidc < 3)
    {
      logprint("%s ipidc %d\n", addr, ipidc);
      sc_target_free(target);
      goto done;
    }

  for(u16=0; u16+2 < ipidc; u16++)
    {
      if(ipid_inseq3(p[u16].ipid, p[u16+1].ipid, p[u16+2].ipid) == 0)
	{
	  logprint("%s not inseq %d\n", addr, u16);
	  sc_target_free(target);
	  goto done;
	}
    }

  logprint("%s incr\n", addr);
  if(sc_target_sample(target, &p[ipidc-1]) == NULL)
    return -1;
  slist_tail_push(incr, target);

 done:
  if(splaytree_count(targets) == 0 && slist_count(probelist) == 0 &&
     heap_count(waiting) == 0)
    {
      if(mode_ok(MODE_DESCEND) == 0)
	return 0;
      mode = MODE_DESCEND;
      for(sn=slist_head_node(incr); sn != NULL; sn=slist_node_next(sn))
	{
	  target = slist_node_item(sn);
	  sc_target_set(target, 0, 0, NULL);
	  slist_tail_push(probelist, target);
	}
      slist_qsort(probelist, (slist_cmp_t)sc_target_ipid_cmp);
      if((descend = slist_alloc()) == NULL)
	return -1;
    }

  return 0;
}

static int reply_descend(sc_target_t *target, sc_targetipid_t *ipids,
			 uint16_t ipidc, uint16_t rxd)
{
  sc_targetipid_t *ti;
  sc_targetset_t *ts;
  struct timeval tv;

  if(ipidc == 0)
    {
      if(target->attempt >= 2)
	goto done;
      if(rxd > 0)
	target->ptb = 1;
      target->attempt++;
      timeval_add_s(&tv, &now, 1);
      if(sc_wait(&tv, target) != 0)
	return -1;
      return 0;
    }

  if((ti = sc_target_sample(target, &ipids[0])) == NULL)
    return -1;
  if(slist_tail_push(descend, ti) == NULL)
    return -1;

 done:
  if(splaytree_count(targets) == 0 && slist_count(probelist) == 0 &&
     heap_count(waiting) == 0)
    {
      if(mode_ok(MODE_OVERLAP) == 0)
	return 0;
      mode = MODE_OVERLAP;

      slist_qsort(descend, (slist_cmp_t)sc_targetipid_tx_cmp);
      ts = NULL;
      while((ti = slist_head_pop(descend)) != NULL)
	{
	  if(ts == NULL || timeval_cmp(&tv, &ti->tx) <= 0)
	    {
	      timeval_cpy(&tv, &ti->rx);
	      if((ts = sc_targetset_alloc()) == NULL || 
		 slist_tail_push(probelist, ts) == NULL)
		return -1;
	      timeval_cpy(&ts->min, &ti->tx);
	      timeval_cpy(&ts->max, &ti->rx);
	    }
	  else
	    {
	      if(timeval_cmp(&ts->max, &ti->rx) < 0)
		timeval_cpy(&ts->max, &ti->rx);
	    }
	  slist_tail_push(ts->targets, ti->target);
	}
      slist_free(descend); descend = NULL;
      overlap_dump();
    }

  return 0;
}

static int reply_overlap(sc_target_t *target, sc_targetipid_t *ipids,
			 uint16_t ipidc, uint16_t rxd)
{
  sc_targetipid_t *ti;
  sc_targetset_t *ts, *tt;
  sc_target_t *tg;
  slist_node_t *sn;
  struct timeval tv;

  if(ipidc == 0)
    {
      if(target->attempt >= 2)
	goto done;
      if(rxd > 0)
	target->ptb = 1;
      target->attempt++;
      timeval_add_s(&tv, &now, 1);
      if(sc_wait(&tv, target) != 0)
	return -1;
      return 0;
    }

  if((ti = sc_target_sample(target, &ipids[0])) == NULL)
    return -1;

 done:
  ts = target->data;
  if(ts->next != NULL)
    {
      tg = slist_node_item(ts->next);
      sc_target_set(tg, 0, 0, ts);
      ts->next = slist_node_next(ts->next);
      timeval_add_s(&tv, &now, 1);
      if(sc_wait(&tv, tg) != 0)
	return -1;
    }
  else
    {
      if(slist_count(ts->blocked) > 0)
	{
	  while((tt = slist_head_pop(ts->blocked)) != NULL)
	    slist_tail_push(probelist, tt);
	  slist_qsort(probelist, (slist_cmp_t)sc_targetset_min_cmp);
	}
      dlist_node_pop(overlap_act, ts->node);
      sc_targetset_free(ts);
    }

  if(splaytree_count(targets) == 0 && slist_count(probelist) == 0 &&
     heap_count(waiting) == 0)
    {
      if(mode_ok(MODE_DESCEND2) == 0)
	return 0;
      mode = MODE_DESCEND2;
      for(sn=slist_head_node(incr); sn != NULL; sn=slist_node_next(sn))
	{
	  target = slist_node_item(sn);
	  sc_target_set(target, 0, 0, NULL);
	  if(target->last != NULL)
	    slist_tail_push(probelist, target);
	}
      slist_qsort(probelist, (slist_cmp_t)sc_target_ipid_cmp);
    }

  return 0;
}

static int finish_descend2(void)
{
  sc_targetset_t *ts;
  slist_t *list = NULL;
  int tc;

  if(mode_ok(MODE_CANDIDATES) == 0)
    goto done;
  mode = MODE_CANDIDATES;

  if((list = slist_alloc()) == NULL || pairwise_all(incr, list) != 0)
    goto err;
  while((ts = slist_head_pop(list)) != NULL)
    {
      tc = slist_count(ts->targets);
      if(slist_tail_push(tc > 3 ? probelist : candidates, ts) == NULL)
	goto err;
    }
  if(slist_count(probelist) == 0)
    {
      if(mode_ok(MODE_ALLY) == 0)
	goto done;
      mode = MODE_ALLY;
      slist_concat(probelist, candidates);
    }
  else
    {
      slist_qsort(probelist, (slist_cmp_t)sc_targetset_targetcount_cmp);
    }

 done:
  if(list != NULL) slist_free(list);
  return 0;

 err:
  if(list != NULL) slist_free(list);
  return -1;
}

static int reply_descend2(sc_target_t *target, sc_targetipid_t *ipids,
			  uint16_t ipidc, uint16_t rxd)
{
  struct timeval tv;

  if(ipidc == 0 && target->attempt < 2)
    {
      if(rxd > 0)
	target->ptb = 1;
      target->attempt++;
      timeval_add_s(&tv, &now, 1);
      if(sc_wait(&tv, target) != 0)
	return -1;
      return 0;
    }

  if(ipidc > 0 && sc_target_sample(target, &ipids[0]) == NULL)
    return -1;

  if(splaytree_count(targets) == 0 && slist_count(probelist) == 0 &&
     heap_count(waiting) == 0 && finish_descend2() != 0)
    return -1;

  return 0;
}

static int finish_candidates(void)
{
  sc_targetset_t *ts;
  slist_node_t *sn;

  if(mode_ok(MODE_ALLY) == 0)
    return 0;
  mode = MODE_ALLY;

  while((ts = slist_head_pop(candidates)) != NULL)
    {
      if(slist_count(ts->targets) > 3)
	{
	  if(pairwise_all(ts->targets, probelist) != 0)
	    return -1;
	  sc_targetset_free(ts);
	}
      else
	{
	  if(slist_tail_push(probelist, ts) == NULL)
	    return -1;
	}
    }

  slist_qsort(probelist, (slist_cmp_t)sc_targetset_targetcount_cmp);
  for(sn=slist_head_node(probelist); sn != NULL; sn=slist_node_next(sn))
    sc_targetset_print(slist_node_item(sn));

  return 0;
}

static int reply_candidates(sc_target_t *target, sc_targetipid_t *ipids,
			    uint16_t ipidc, uint16_t rxd)
{
  sc_targetipid_t *ti = NULL;
  sc_targetset_t *ts = target->data;
  sc_target_t *tg = NULL, *t1, *t2;
  slist_node_t *s2 = NULL;
  struct timeval tv;

  timeval_add_s(&tv, &now, 1);

  if(ipidc == 0)
    {
      if(target->attempt >= 2)
	goto done;
      if(rxd > 0)
	target->ptb = 1;
      target->attempt++;
      if(sc_wait(&tv, target) != 0)
	return -1;
      return 0;
    }

  if((ti = sc_target_sample(target, &ipids[0])) == NULL)
    return -1;

 done:
  t1 = ts->s1 != NULL ? slist_node_item(ts->s1) : NULL;
  t2 = ts->s2 != NULL ? slist_node_item(ts->s2) : NULL;

  if(target == t2 && ti != NULL && pairwise(t1, t2) == 1)
    {
      tg = t1;
    }
  else
    {
      /* advance to the next t2, if available */
      if(ts->s2 == NULL)
	s2 = slist_node_next(ts->s1);
      else
	s2 = slist_node_next(ts->s2);
      while(s2 != NULL)
	{
	  if(pairwise(t1, slist_node_item(s2)) == 1)
	    break;
	  s2 = slist_node_next(s2);
	}

      if(s2 != NULL)
	{
	  ts->s2 = s2;
	  tg = slist_node_item(s2);
	}
      else
	{
	  ts->s1 = slist_node_next(ts->s1);
	  ts->s2 = NULL;
	  if(slist_node_next(ts->s1) == NULL)
	    ts->s1 = NULL;
	  if(ts->s1 != NULL)
	    tg = slist_node_item(ts->s1);
	}
    }

  if(tg != NULL)
    {
      sc_target_set(tg, 0, 0, ts);
      if(sc_wait(&tv, tg) != 0)
	return -1;
    }
  else
    {
      slist_tail_push(candidates, ts);
    }

  if(splaytree_count(targets) == 0 && slist_count(probelist) == 0 &&
     heap_count(waiting) == 0 && finish_candidates() != 0)
    return -1;

  return 0;
}

static int do_decoderead_ping(scamper_ping_t *ping)
{
  static int (*const func[])(sc_target_t *, sc_targetipid_t *,
			     uint16_t, uint16_t) = {
    reply_classify,
    reply_descend,
    reply_overlap,
    reply_descend2,
    reply_candidates,
  };
  sc_target_t            *target;
  char                    buf[64];
  scamper_ping_reply_t   *reply;
  int                     rc = -1;
  sc_targetipid_t         p[6];
  uint16_t                u16;
  uint16_t                probes_rxd = 0;
  uint16_t                ipids_rxd = 0;

  if((target = sc_target_findtree(ping->dst)) == NULL)
    {
      fprintf(stderr, "do_decoderead: could not find dst %s\n",
	      scamper_addr_tostr(ping->dst, buf, sizeof(buf)));
      goto done;
    }
  sc_target_detachtree(target);

  for(u16=0; u16<ping->ping_sent; u16++)
    {
      if((reply = ping->ping_replies[u16]) == NULL ||
	 SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) == 0)
	continue;
      probes_rxd++;
      if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
	{
	  timeval_cpy(&p[ipids_rxd].tx, &reply->tx);
	  timeval_add_tv3(&p[ipids_rxd].rx, &reply->tx, &reply->rtt);
	  p[ipids_rxd].ipid = reply->reply_ipid32;
	  ipids_rxd++;
	}
    }
  scamper_ping_free(ping); ping = NULL;

  rc = func[mode](target, p, ipids_rxd, probes_rxd);

 done:
  if(ping != NULL) scamper_ping_free(ping);
  return rc;
}

static int do_decoderead_dealias(scamper_dealias_t *dealias)
{
  scamper_dealias_ally_t *ally = dealias->data;
  sc_targetset_t *ts;
  sc_target_t *target;
  struct timeval tv;
  char a[64], b[64], r[16];

  assert(SCAMPER_DEALIAS_METHOD_IS_ALLY(dealias));

  scamper_addr_tostr(ally->probedefs[0].dst, a, sizeof(a));
  scamper_addr_tostr(ally->probedefs[1].dst, b, sizeof(b));

  if((target = sc_target_findtree(ally->probedefs[0].dst)) == NULL)
    {
      fprintf(stderr, "do_decoderead: could not find dst %s\n", a);
      goto done;
    }
  sc_target_detachtree(target);
  ts = target->data;

  if(dealias->result == SCAMPER_DEALIAS_RESULT_NONE)
    {
      if(ts->attempt >= 2)
	sc_targetset_nextpair(ts);
      else
	ts->attempt++;
    }
  else
    {
      if(SCAMPER_DEALIAS_RESULT_IS_ALIASES(dealias) && aliasfile != NULL)
	{
	  fprintf(aliasfile, "%s %s\n", a, b);
	  fflush(aliasfile);
	}
      logprint("%s %s %s\n", a, b,
	       scamper_dealias_result_tostr(dealias,r,sizeof(r)));
      sc_targetset_nextpair(ts);
    }

  if(ts->s1 != NULL)
    {
      timeval_add_s(&tv, &now, 1);
      if(sc_wait(&tv, ts) != 0)
	return -1;
    }
  else
    {
      sc_targetset_free(ts);
    }

 done:
  if(dealias != NULL) scamper_dealias_free(dealias);
  return 0;
}

static int do_decoderead(void)
{
  void     *data;
  uint16_t  type;

  /* try and read a traceroute from the warts decoder */
  if(scamper_file_read(decode_in, ffilter, &type, &data) != 0)
    {
      fprintf(stderr, "do_decoderead: scamper_file_read errno %d\n", errno);
      return -1;
    }
  if(data == NULL)
    return 0;
  probing--;

  if(scamper_file_write_obj(outfile, type, data) != 0)
    {
      fprintf(stderr, "do_decoderead: could not write obj %d\n", type);
      /* XXX: free data */
      return -1;
    }

  if(type == SCAMPER_FILE_OBJ_PING)
    return do_decoderead_ping(data);
  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
    return do_decoderead_dealias(data);

  return -1;
}

static int do_scamperread(void)
{
  ssize_t rc;
  uint8_t uu[64];
  char   *ptr, *head;
  char    buf[512];
  void   *tmp;
  long    l;
  size_t  i, uus, linelen;

  if((rc = read(scamper_fd, buf, sizeof(buf))) > 0)
    {
      if(readbuf_len == 0)
	{
	  if((readbuf = memdup(buf, rc)) == NULL)
	    {
	      return -1;
	    }
	  readbuf_len = rc;
	}
      else
	{
	  if((tmp = realloc(readbuf, readbuf_len + rc)) != NULL)
	    {
	      readbuf = tmp;
	      memcpy(readbuf+readbuf_len, buf, rc);
	      readbuf_len += rc;
	    }
	  else return -1;
	}
    }
  else if(rc == 0)
    {
      close(scamper_fd);
      scamper_fd = -1;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }
  else
    {
      fprintf(stderr, "could not read: errno %d\n", errno);
      return -1;
    }

  /* process whatever is in the readbuf */
  if(readbuf_len == 0)
    {
      goto done;
    }

  head = readbuf;
  for(i=0; i<readbuf_len; i++)
    {
      if(readbuf[i] == '\n')
	{
	  /* skip empty lines */
	  if(head == &readbuf[i])
	    {
	      head = &readbuf[i+1];
	      continue;
	    }

	  /* calculate the length of the line, excluding newline */
	  linelen = &readbuf[i] - head;

	  /* if currently decoding data, then pass it to uudecode */
	  if(data_left > 0)
	    {
	      uus = sizeof(uu);
	      if(uudecode_line(head, linelen, uu, &uus) != 0)
		{
		  fprintf(stderr, "could not uudecode_line\n");
		  goto err;
		}

	      if(uus != 0)
		write_wrap(decode_out_fd, uu, NULL, uus);

	      data_left -= (linelen + 1);
	    }
	  /* if the scamper process is asking for more tasks, give it more */
	  else if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
	    {
	      more++;
	      if(do_method() != 0)
		goto err;
	    }
	  /* new piece of data */
	  else if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
	    {
	      l = strtol(head+5, &ptr, 10);
	      if(*ptr != '\n' || l < 1)
		{
		  head[linelen] = '\0';
		  fprintf(stderr, "could not parse %s\n", head);
		  goto err;
		}

	      data_left = l;
	    }
	  /* feedback letting us know that the command was accepted */
	  else if(linelen >= 2 && strncasecmp(head, "OK", 2) == 0)
	    {
	      /* nothing to do */
	    }
	  /* feedback letting us know that the command was not accepted */
	  else if(linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
	    {
	      more++;
	      if(do_method() != 0)
		goto err;
	    }
	  else
	    {
	      head[linelen] = '\0';
	      fprintf(stderr, "unknown response '%s'\n", head);
	      goto err;
	    }

	  head = &readbuf[i+1];
	}
    }

  if(head != &readbuf[readbuf_len])
    {
      readbuf_len = &readbuf[readbuf_len] - head;
      ptr = memdup(head, readbuf_len);
      free(readbuf);
      readbuf = ptr;
    }
  else
    {
      readbuf_len = 0;
      free(readbuf);
      readbuf = NULL;
    }

 done:
  return 0;

 err:
  return -1;
}

static void cleanup(void)
{
  sc_target_t *tg;

  if(pairwise_uint32 != NULL)
    {
      free(pairwise_uint32);
      pairwise_uint32 = NULL;
    }

  if(pairwise_tipid != NULL)
    {
      free(pairwise_tipid);
      pairwise_tipid = NULL;
    }

  if(descend != NULL)
    {
      slist_free(descend);
      descend = NULL;
    }

  if(targets != NULL)
    {
      splaytree_free(targets, NULL);
      targets = NULL;
    }

  if(incr != NULL)
    {
      while((tg = slist_head_pop(incr)) != NULL)
	sc_target_free(tg);
      slist_free(incr);
      incr = NULL;
    }

  if(candidates != NULL)
    {
      slist_free(candidates);
      candidates = NULL;
    }

  if(overlap_act != NULL)
    {
      dlist_free(overlap_act);
      overlap_act = NULL;
    }

  if(probelist != NULL)
    {
      slist_free(probelist);
      probelist = NULL;
    }

  if(skiptree != NULL)
    {
      splaytree_free(skiptree, (splaytree_free_t)sc_skippair_free);
      skiptree = NULL;
    }

  if(waiting != NULL)
    {
      heap_free(waiting, NULL);
      waiting = NULL;
    }

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  if(decode_in != NULL)
    {
      scamper_file_close(decode_in);
      decode_in = NULL;
    }

  if(ffilter != NULL)
    {
      scamper_file_filter_free(ffilter);
      ffilter = NULL;
    }

  return;
}

static int speedtrap_data(void)
{
  struct timeval tv, *tv_ptr;
  sc_wait_t *w;
  fd_set rfds;
  int nfds;

  if((targets = splaytree_alloc((splaytree_cmp_t)sc_target_addr_cmp)) == NULL)
    return -1;
  if((waiting = heap_alloc(sc_wait_cmp)) == NULL)
    return -1;
  if((probelist = slist_alloc()) == NULL)
    return -1;
  if((incr = slist_alloc()) == NULL)
    return -1;
  if((candidates = slist_alloc()) == NULL)
    return -1;
  if((overlap_act = dlist_alloc()) == NULL)
    return -1;
  if((skiptree = splaytree_alloc((splaytree_cmp_t)sc_skippair_cmp)) == NULL)
    return -1;

  if(do_addressfile() != 0)
    return -1;
  if(do_skipfile() != 0)
    return -1;
  if(do_scamperconnect() != 0)
    return -1;
  if(do_files() != 0)
    return -1;

  gettimeofday_wrap(&tv);
  srandom(tv.tv_usec);

  slist_shuffle(probelist);

  /* attach */
  if(write_wrap(scamper_fd, "attach\n", NULL, 7) != 0)
    {
      fprintf(stderr, "could not attach to scamper process\n");
      return -1;
    }

  if(options & OPT_INCR)
    {
      mode = MODE_DESCEND;
      if((descend = slist_alloc()) == NULL)
	return -1;
    }

  for(;;)
    {
      nfds = 0;
      FD_ZERO(&rfds);

      if(scamper_fd < 0 && decode_in_fd < 0)
	break;

      if(scamper_fd >= 0)
	{
	  FD_SET(scamper_fd, &rfds);
	  if(nfds < scamper_fd) nfds = scamper_fd;
	}

      if(decode_in_fd >= 0)
	{
	  FD_SET(decode_in_fd, &rfds);
	  if(nfds < decode_in_fd) nfds = decode_in_fd;
	}

      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is a trace in the waiting queue.
       */
      tv_ptr = NULL;
      if(more > 0)
	{
	  gettimeofday_wrap(&now);

	  /*
	   * if there is something ready to probe now, then try and
	   * do it.
	   */
	  w = heap_head_item(waiting);
	  if(slist_count(probelist) > 0 ||
	     (w != NULL && timeval_cmp(&w->tv, &now) <= 0))
	    {
	      if(do_method() != 0)
		return -1;
	    }

	  /*
	   * if we could not send a new command just yet, but scamper
	   * wants one, then wait for an appropriate length of time.
	   */
	  w = heap_head_item(waiting);
	  if(more > 0 && tv_ptr == NULL && w != NULL)
	    {
	      tv_ptr = &tv;
	      if(timeval_cmp(&w->tv, &now) > 0)
		timeval_diff_tv(&tv, &now, &w->tv);
	      else
		memset(&tv, 0, sizeof(tv));
	    }
	}

      if(splaytree_count(targets) == 0 && slist_count(probelist) == 0 &&
	 heap_count(waiting) == 0)
	{
	  logprint("done\n");
	  break;
	}

      if(select(nfds+1, &rfds, NULL, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  fprintf(stderr, "select error\n");
	  break;
	}

      gettimeofday_wrap(&now);

      if(more > 0)
	{
	  if(do_method() != 0)
	    return -1;
	}

      if(scamper_fd >= 0 && FD_ISSET(scamper_fd, &rfds))
	{
	  if(do_scamperread() != 0)
	    return -1;
	}

      if(decode_in_fd >= 0 && FD_ISSET(decode_in_fd, &rfds))
	{
	  if(do_decoderead() != 0)
	    return -1;
	}
    }

  return 0;
}

static int speedtrap_read(void)
{
  scamper_file_t *in;
  char *filename;
  uint16_t type;
  void *data;
  int i;

  for(i=0; i<dump_filec; i++)
    {
      filename = dump_files[i]; dump_stop = 0;
      if((in = scamper_file_open(filename, 'r', NULL)) == NULL)
	{
	  fprintf(stderr,"could not open %s: %s\n", filename, strerror(errno));
	  return -1;
	}

      while(scamper_file_read(in, ffilter, &type, &data) == 0)
	{
	  /* EOF */
	  if(data == NULL)
	    break;

	  if(type == SCAMPER_FILE_OBJ_PING)
	    {
	      if(dump_funcs[dump_id].proc_ping != NULL)
		dump_funcs[dump_id].proc_ping(data);
	      scamper_ping_free(data);
	    }
	  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
	    {
	      if(dump_funcs[dump_id].proc_ally != NULL)
		dump_funcs[dump_id].proc_ally(data);
	      scamper_dealias_free(data);
	    }

	  if(dump_stop != 0)
	    break;
	}

      scamper_file_close(in);
    }

  if(dump_funcs[dump_id].finish != NULL)
    dump_funcs[dump_id].finish();

  return 0;
}

static int speedtrap_init(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING, SCAMPER_FILE_OBJ_DEALIAS};
  int typec   = sizeof(types) / sizeof(uint16_t);
  if((ffilter = scamper_file_filter_alloc(types, typec)) == NULL)
    return -1;
  return 0;
}

int main(int argc, char *argv[])
{
#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  if(speedtrap_init() != 0)
    return -1;

  if(options & OPT_DUMP)
    return speedtrap_read();
  else
    return speedtrap_data();

  return 0;
}
