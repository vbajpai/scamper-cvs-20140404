/*
 * scamper_trace_json.c
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2011-2013 Internap Network Services Corporation
 * Copyright (C) 2013      The Regents of the University of California
 * Authors: Brian Hammond, Matthew Luckie
 *
 * $Id: scamper_trace_json.c,v 1.5 2014/01/10 18:05:40 mjl Exp $
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
  "$Id: scamper_trace_json.c,v 1.5 2014/01/10 18:05:40 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_trace.h"
#include "scamper_file.h"
#include "scamper_trace_json.h"
#include "utils.h"

static char *hop_tostr(scamper_trace_hop_t *hop)
{
  char buf[512], tmp[128];
  size_t off = 0;

  string_concat(buf, sizeof(buf), &off,	"{\"addr\":\"%s\"",
		scamper_addr_tostr(hop->hop_addr, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off,
		", \"probe_ttl\":%u, \"probe_id\":%u, \"probe_size\":%u", 
		hop->hop_probe_ttl, hop->hop_probe_id, hop->hop_probe_size);
  string_concat(buf, sizeof(buf), &off, ", \"rtt\":%s",
		timeval_tostr(&hop->hop_rtt, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off,
		", \"reply_ttl\":%u, \"reply_tos\":%u, \"reply_size\":%u",
		hop->hop_reply_ttl, hop->hop_reply_tos, hop->hop_reply_size);
  string_concat(buf, sizeof(buf), &off,	", \"reply_ipid\":%u",
		hop->hop_reply_ipid);

  if(SCAMPER_TRACE_HOP_IS_ICMP(hop))
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"icmp_type\":%u, \"icmp_code\":%u",
		    hop->hop_icmp_type, hop->hop_icmp_code);
      if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop))
	{
	  string_concat(buf, sizeof(buf), &off,
			", \"icmp_q_ttl\":%u, \"icmp_q_ipl\":%u",
			hop->hop_icmp_q_ttl, hop->hop_icmp_q_ipl);
	  if(SCAMPER_ADDR_TYPE_IS_IPV4(hop->hop_addr))
	    string_concat(buf, sizeof(buf), &off, ", \"icmp_q_tos\":%u",
			  hop->hop_icmp_q_tos);
	}
      if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop))
	string_concat(buf, sizeof(buf), &off, ", \"icmp_nhmtu:\":%u",
		      hop->hop_icmp_nhmtu);
    }
  else
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"tcp_flags\":%u", hop->hop_tcp_flags);
    }
  string_concat(buf, sizeof(buf), &off, "}");
  return strdup(buf);
}

static char *stop_reason_tostr(uint8_t reason, char *buf, size_t len)
{
  static char *r[] = {
    "NONE",
    "COMPLETED",
    "UNREACH",
    "ICMP",
    "LOOP",
    "GAPLIMIT",
    "ERROR",
    "HOPLIMIT",
    "GSS",
  };
  if(reason > sizeof(r) / sizeof(char *))
    {
      snprintf(buf, len, "%d", reason);
      return buf;
    }
  return r[reason];
}

static char *header_tostr(const scamper_trace_t *trace)
{
  char buf[512], tmp[64];
  const char *ptr;
  size_t off = 0;
  time_t tt = trace->start.tv_sec;

  string_concat(buf, sizeof(buf), &off, "\"version\":\"0.1\",\"type\":\"trace\"");
  string_concat(buf, sizeof(buf), &off, ", \"userid\":%u", trace->userid);
  if((ptr = scamper_trace_type_tostr(trace)) != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"method\":\"%s\"", ptr);
  else
    string_concat(buf, sizeof(buf), &off, ", \"method\":\"%u\"", trace->type);
  string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		scamper_addr_tostr(trace->src, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		scamper_addr_tostr(trace->dst, tmp, sizeof(tmp)));
  if(SCAMPER_TRACE_TYPE_IS_UDP(trace) || SCAMPER_TRACE_TYPE_IS_TCP(trace))
    string_concat(buf, sizeof(buf), &off, ", \"sport\":%u, \"dport\":%u",
		  trace->sport, trace->dport);
  else if(trace->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)
    string_concat(buf, sizeof(buf), &off, ", \"icmp_sum\":%u", trace->dport);
  string_concat(buf, sizeof(buf), &off,
		", \"stop_reason\":\"%s\", \"stop_data\":%u",
		stop_reason_tostr(trace->stop_reason, tmp, sizeof(tmp)),
		trace->stop_data);
  strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&tt));
  string_concat(buf, sizeof(buf), &off,
		", \"start\":{\"sec\":%u, \"usec\":%u, \"ftime\":\"%s\"}",
		trace->start.tv_sec, trace->start.tv_usec, tmp);
  string_concat(buf, sizeof(buf), &off,
		", \"hop_count\":%u, \"attempts\":%u, \"hoplimit\":%u",
		trace->hop_count, trace->attempts, trace->hoplimit);
  string_concat(buf, sizeof(buf), &off,
		", \"firsthop\":%u, \"wait\":%u, \"wait_probe\":%u",
		trace->firsthop, trace->wait, trace->wait_probe);
  string_concat(buf, sizeof(buf), &off,	", \"tos\":%u, \"probe_size\":%u",
		trace->tos, trace->probe_size);

  return strdup(buf);
}

int scamper_file_json_trace_write(const scamper_file_t *sf,
				  const scamper_trace_t *trace)
{
  scamper_trace_hop_t *hop;
  int fd = scamper_file_getfd(sf);
  size_t wc, len, off = 0;
  off_t foff = 0;
  char *str = NULL, *header = NULL, **hops = NULL;
  int i, j, hopc = 0, rc = -1;

  if(fd != STDOUT_FILENO && (foff = lseek(fd, 0, SEEK_CUR)) == -1)
    return -1;

  if((header = header_tostr(trace)) == NULL)
    goto cleanup;
  len = strlen(header);

  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
      hopc++;
  if(hopc > 0)
    {
      len += 11; /* , "hops":[] */
      if((hops = malloc_zero(sizeof(char *) * hopc)) == NULL)
	goto cleanup;
      for(i=trace->firsthop-1, j=0; i<trace->hop_count; i++)
	{
	  for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	    {
	      if(j > 0) len++; /* , */
	      if((hops[j] = hop_tostr(hop)) == NULL)
		goto cleanup;
	      len += strlen(hops[j]);
	      j++;
	    }
	}
    }
  len += 4; /* {}\n\0 */

  if((str = malloc(len)) == NULL)
    goto cleanup;

  string_concat(str, len, &off, "{%s", header);
  if(hopc > 0)
    {
      string_concat(str, len, &off, ", \"hops\":[");
      for(j=0; j<hopc; j++)
	{
	  if(j > 0) string_concat(str, len, &off, ",");
	  string_concat(str, len, &off, "%s", hops[j]);
	}
      string_concat(str, len, &off, "]");
    }
  string_concat(str, len, &off, "}\n");
  assert(off+1 == len);

  if(write_wrap(fd, str, &wc, off) != 0)
    {
      if(fd != STDOUT_FILENO)
	{
	  if(ftruncate(fd, foff) != 0)
	    goto cleanup;
	}
      goto cleanup;
    }

  rc = 0; /* we succeeded */

 cleanup:
  if(hops != NULL)
    {
      for(i=0; i<hopc; i++)
	if(hops[i] != NULL)
	  free(hops[i]);
      free(hops);
    }
  if(header != NULL) free(header);
  if(str != NULL) free(str);

  return rc;
}
