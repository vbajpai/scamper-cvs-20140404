/*
 * scamper_ping_json.c
 *
 * Copyright (c) 2005-2006 Matthew Luckie
 * Copyright (c) 2006-2011 The University of Waikato
 * Copyright (c) 2011-2013 Internap Network Services Corporation
 * Copyright (c) 2013      Matthew Luckie
 * Copyright (c) 2013-2014 The Regents of the University of California
 * Authors: Brian Hammond, Matthew Luckie
 *
 * $Id: scamper_ping_json.c,v 1.8 2014/03/06 20:24:37 mjl Exp $
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
  "$Id: scamper_ping_json.c,v 1.8 2014/03/06 20:24:37 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_file.h"
#include "scamper_ping_json.h"

#include "utils.h"

static char *ping_header(const scamper_ping_t *ping)
{
  char buf[512], tmp[64];
  size_t off = 0;
  uint8_t u8;

  string_concat(buf, sizeof(buf), &off,
		"{\"version\":\"0.2\", \"type\":\"ping\", \"method\":\"%s\"",
		scamper_ping_method2str(ping, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		scamper_addr_tostr(ping->src, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		scamper_addr_tostr(ping->dst, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off,
		", \"start\":{\"sec\":%u,\"usec\":%u}",
		ping->start.tv_sec, ping->start.tv_usec);
  string_concat(buf, sizeof(buf), &off,
		", \"ping_sent\":%u, \"probe_size\":%u"
		", \"userid\":%u, \"ttl\":%u, \"wait\":%u",
		ping->ping_sent, ping->probe_size,
		ping->userid, ping->probe_ttl, ping->probe_wait);
  if(ping->probe_wait_us != 0)
    string_concat(buf, sizeof(buf), &off,
		  ", \"wait_us\":%u", ping->probe_wait_us);
  string_concat(buf, sizeof(buf), &off,
		", \"timeout\":%u", ping->probe_timeout);

  if(SCAMPER_PING_METHOD_IS_UDP(ping) || SCAMPER_PING_METHOD_IS_TCP(ping))
    string_concat(buf, sizeof(buf), &off, ", \"sport\":%u, \"dport\":%u",
		  ping->probe_sport, ping->probe_dport);

  if(SCAMPER_PING_METHOD_IS_ICMP(ping) &&
     (ping->flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
    string_concat(buf, sizeof(buf), &off,
		  ", \"icmp_csum\": %u",ping->probe_icmpsum);

  if(ping->probe_tsps != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"probe_tsps\":[");
      for(u8=0; u8<ping->probe_tsps->ipc; u8++)
	{
	  if(u8 > 0) string_concat(buf, sizeof(buf), &off, ",");
	  scamper_addr_tostr(ping->probe_tsps->ips[u8], tmp, sizeof(tmp));
	  string_concat(buf, sizeof(buf), &off, "\"%s\"", tmp);
	}
      string_concat(buf, sizeof(buf), &off, "]");
    }

  return strdup(buf);
}

static char *ping_reply(const scamper_ping_t *ping,
			const scamper_ping_reply_t *reply)
{
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  struct timeval tv;
  char buf[512], tmp[64];
  uint8_t i;
  size_t off = 0;

  string_concat(buf, sizeof(buf), &off,	"{\"from\":\"%s\", \"seq\":%u",
		scamper_addr_tostr(reply->addr, tmp, sizeof(tmp)),
		reply->probe_id);
  string_concat(buf, sizeof(buf), &off,", \"reply_size\":%u, \"reply_ttl\":%u",
		reply->reply_size, reply->reply_ttl);
  if(reply->tx.tv_sec != 0)
    {
      timeval_add_tv3(&tv, &reply->tx, &reply->rtt);
      string_concat(buf, sizeof(buf), &off,
		    ", \"tx\":{\"sec\":%u, \"usec\":%u}",
		    reply->tx.tv_sec, reply->tx.tv_usec);
      string_concat(buf, sizeof(buf), &off,
		    ", \"rx\":{\"sec\":%u, \"usec\":%u}",
		    tv.tv_sec, tv.tv_usec);
    }
  string_concat(buf, sizeof(buf), &off, ", \"rtt\":%s",
		timeval_tostr(&reply->rtt, tmp, sizeof(tmp)));

  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->addr))
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"probe_ipid\":%u, \"reply_ipid\":%u",
		    reply->probe_ipid, reply->reply_ipid);
    }

  if(SCAMPER_PING_REPLY_IS_ICMP(reply))
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"icmp_type\":%u, \"icmp_code\":%u",
		    reply->icmp_type, reply->icmp_code);
    }
  else if(SCAMPER_PING_REPLY_IS_TCP(reply))
    {
      string_concat(buf, sizeof(buf), &off, ", \"tcp_flags\":%u",
		    reply->tcp_flags);
    }

  if((v4rr = reply->v4rr) != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"RR\":[");
      for(i=0; i<v4rr->rrc; i++)
	{
	  if(i > 0) string_concat(buf, sizeof(buf), &off, ",");
	  string_concat(buf, sizeof(buf), &off, "\"%s\"",
			scamper_addr_tostr(v4rr->rr[i], tmp, sizeof(tmp)));
	}
      string_concat(buf, sizeof(buf), &off, "]");
    }

  if((v4ts = reply->v4ts) != NULL)
    {
      if((ping->flags & SCAMPER_PING_FLAG_TSONLY) == 0)
	{
	  string_concat(buf, sizeof(buf), &off, ", \"tsandaddr\":[");
	  for(i=0; i<v4ts->tsc; i++)
	    {
	      if(i > 0) string_concat(buf, sizeof(buf), &off, ",");
	      string_concat(buf,sizeof(buf),&off, "{\"ip\":\"%s\",\"ts\":%u}",
			    scamper_addr_tostr(v4ts->ips[i], tmp, sizeof(tmp)),
			    v4ts->tss[i]);
	    }
	  string_concat(buf, sizeof(buf), &off, "]");
	}
      else
	{
	  string_concat(buf, sizeof(buf), &off, ", \"tsonly\":[");
	  for(i=0; i<v4ts->tsc; i++)
	    {
	      if(i > 0) string_concat(buf, sizeof(buf), &off, ",");
	      string_concat(buf, sizeof(buf), &off, "%u", v4ts->tss[i]);
	    }
	  string_concat(buf, sizeof(buf), &off, "]");
	}
    }

  string_concat(buf, sizeof(buf), &off, "}");

  return strdup(buf);
}

static char *ping_stats(const scamper_ping_t *ping)
{
  scamper_ping_stats_t stats;
  char buf[512], str[64];
  size_t off = 0;

  if(scamper_ping_stats(ping, &stats) != 0)
    return NULL;

  string_concat(buf, sizeof(buf), &off, "\"statistics\":{\"replies\":%d",
		stats.nreplies);

  if(ping->ping_sent != 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"loss\":");

      if(stats.nreplies == 0)
	string_concat(buf, sizeof(buf), &off, "1");
      else if(stats.nreplies == ping->ping_sent)
	string_concat(buf, sizeof(buf), &off, "0");
      else
	string_concat(buf, sizeof(buf), &off, "%.2f",
		      (float)(ping->ping_sent - stats.nreplies)
		      / ping->ping_sent);
    }
  if(stats.nreplies > 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"min\":%s",
		    timeval_tostr(&stats.min_rtt, str, sizeof(str)));
      string_concat(buf, sizeof(buf), &off, ", \"max\":%s",
		    timeval_tostr(&stats.max_rtt, str, sizeof(str)));
      string_concat(buf, sizeof(buf), &off, ", \"avg\":%s",
		    timeval_tostr(&stats.avg_rtt, str, sizeof(str)));
      string_concat(buf, sizeof(buf), &off, ", \"stddev\":%s",
		    timeval_tostr(&stats.stddev_rtt, str, sizeof(str)));
    }
  string_concat(buf, sizeof(buf), &off, "}");

  return strdup(buf);
}

int scamper_file_json_ping_write(const scamper_file_t *sf,
				 const scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  int       fd          = scamper_file_getfd(sf);
  off_t     off         = 0;
  uint32_t  reply_count = scamper_ping_reply_count(ping);
  char     *header      = NULL;
  size_t    header_len  = 0;
  char    **replies     = NULL;
  size_t   *reply_lens  = NULL;
  char     *stats       = NULL;
  size_t    stats_len   = 0;
  char     *str         = NULL;
  size_t    len         = 0;
  size_t    wc          = 0;
  int       ret         = -1;
  uint32_t  i,j;

  /* get current position incase trunction is required */
  if(fd != 1 && (off = lseek(fd, 0, SEEK_CUR)) == -1)
    return -1;

  /* get the header string */
  if((header = ping_header(ping)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  /* put together a string for each reply */
  len += 15; /* , \"responses\":[", */
  if(reply_count > 0)
    {
      if((replies    = malloc_zero(sizeof(char *) * reply_count)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * reply_count)) == NULL)
	{
	  goto cleanup;
	}

      for(i=0, j=0; i<ping->ping_sent; i++)
	{
	  reply = ping->ping_replies[i];
	  while(reply != NULL)
	    {
	      /* build string representation of this reply */
	      if((replies[j] = ping_reply(ping, reply)) == NULL)
		goto cleanup;
	      len += (reply_lens[j] = strlen(replies[j]));
	      if(j > 0) len++; /* , */
	      reply = reply->next;
	      j++;
	    }
	}
    }
  len += 2; /* ], */
  if((stats = ping_stats(ping)) != NULL)
    len += (stats_len = strlen(stats));
  len += 2; /* }\n */

  if((str = malloc(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"responses\":[", 15); wc += 15;
  for(i=0; i<reply_count; i++)
    {
      if(i > 0)
	{
	  memcpy(str+wc, ",", 1);
	  wc++;
	}
      memcpy(str+wc, replies[i], reply_lens[i]);
      wc += reply_lens[i];
    }
  memcpy(str+wc, "],", 2); wc += 2;
  if(stats != NULL)
    {
      memcpy(str+wc, stats, stats_len);
      wc += stats_len;
    }
  memcpy(str+wc, "}\n", 2); wc += 2;

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(write_wrap(fd, str, &wc, len) != 0)
    {
      if(fd != 1)
	{
	  if(ftruncate(fd, off) != 0)
	    goto cleanup;
	}
      goto cleanup;
    }
  ret = 0; /* we succeeded */

 cleanup:
  if(str != NULL) free(str);
  if(header != NULL) free(header);
  if(stats != NULL) free(stats);
  if(reply_lens != NULL) free(reply_lens);
  if(replies != NULL)
    {
      for(i=0; i<reply_count; i++)
	if(replies[i] != NULL)
	  free(replies[i]);
      free(replies);
    }

  return ret;
}
