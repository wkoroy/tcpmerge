#include "libpcap_file_generator.h"
 

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <sys/time.h>

/*******************************************************************************
  *    Project Name: tcpmerge                                                  *
  *    Author:Vladimir Koroy                                                   *
  *    20 dec.  15:54:13   MSK 2017                                            *
  *    This program can be merge pcap files                                    *
  *                                                                            * 
  ******************************************************************************/

typedef struct PCAPFILE_TS
{
    PCAPFILE *f;
    uint32_t start_ts_sec;
    uint32_t start_ts_usec;
    int count_read;
    int is_end;

} PCAPFILE_TS_t;

int gen_test();
int testing();
int check_exists_data_out_file();
unsigned long tm_to_seconds(uint32_t  ts_usec)
{
   time_t tt = ts_usec;
   struct tm  ptm;
   (void) localtime_r(&tt, &ptm);
   unsigned long result = ptm.tm_sec*1+ptm.tm_min*60+ptm.tm_hour*(60*60)+ptm.tm_yday*(60*60*24)+ptm.tm_year*(60*60*24*365);
  return  result;
}

int pt_lpcap_read_frame_record(PCAPFILE_TS_t *pfl, pcaprec_hdr_and_data_t *phdr)
{
    int r = lpcap_read_frame_record(pfl->f, phdr);
    if (r)
    {
      
        if (pfl->count_read == 0)
        {
            pfl->start_ts_sec =  (phdr->pcp_rec_hdr.ts_sec );
            pfl->start_ts_usec= 0;//phdr->pcp_rec_hdr.ts_usec ;
        }

        phdr->pcp_rec_hdr.ts_sec -= pfl->start_ts_sec;
        phdr->pcp_rec_hdr.ts_usec  -= pfl->start_ts_usec;

        pfl->count_read++;
    }
    return r;
}

void print_hdr(pcap_hdr_t *ph)
{
    printf("magic_number %4x \n", ph->magic_number);
    printf(" version_major %2x \n", ph->version_major);
    printf("version_minor %2x \n", ph->version_minor);
    printf("thiszone %d \n", ph->thiszone);
    printf("sigfigs %4x \n", ph->sigfigs);
    printf("snaplen %d \n", ph->snaplen);
    printf("network %d \n", ph->network);
}

void print_rec_hdr(pcaprec_hdr_t *ph)
{
    printf("ts_sec %i \n", (unsigned)ph->ts_sec);
    printf(" ts_usec %i \n", ph->ts_usec);
    printf(" incl_len  %d \n", ph->incl_len);
    printf(" orig_len  %i \n", ph->orig_len);
}

// 0  pr1 == pr2  , 1 pr1 < pr2 ,  -1 pr1>pr2
int rec_compare(pcaprec_hdr_t *pr1, pcaprec_hdr_t *pr2)
{
 
       
    int res = 0;
      long sec1 = tm_to_seconds(pr1->ts_sec) ;
      long sec2 = tm_to_seconds(pr2->ts_sec)  ;
    if (sec1 > sec2)
        res = -1;
    else if (sec1 < sec2)
        res = 1;
    else //sec1 == sec2
    {
        long usec1 = pr1->ts_usec ;
        long usec2 = pr2->ts_usec ;
        if (usec1 > usec2)
            res = -1;
        else if (usec1 < usec2)
            res = 1;
        else
            res = 0;
    }
    return res;
}

int pck_get_next_abst(PCAPFILE_TS_t *pfr, pcaprec_hdr_and_data_t *phdr_data_out) // not multithread!
{
    int start = pfr[0].count_read + pfr[1].count_read;
    static int index_max = 0;
    static pcaprec_hdr_and_data_t phdrd_compare;
    int res_rec_read[2] = {0, 0};
    pcaprec_hdr_and_data_t p_rec_data[2];
    pcaprec_hdr_and_data_t *res_hdrd = &p_rec_data[0];
    if (!start)
    {
        res_rec_read[0] = pt_lpcap_read_frame_record(&pfr[0], &p_rec_data[0]);
        res_rec_read[1] = pt_lpcap_read_frame_record(&pfr[1], &p_rec_data[1]);

        int r_cmpp = rec_compare(&p_rec_data[0].pcp_rec_hdr, &p_rec_data[1].pcp_rec_hdr);
        if (r_cmpp == -1)
        {
            index_max = 0;
        }
        else
            index_max = 1;
        phdrd_compare = p_rec_data[index_max];
        res_hdrd = &p_rec_data[index_max ? 0 : 1];
    }
    else
    {
        res_rec_read[index_max ? 0 : 1] = pt_lpcap_read_frame_record(&pfr[index_max ? 0 : 1], &p_rec_data[index_max ? 0 : 1]);

        if (!res_rec_read[index_max ? 0 : 1])
        {
            if (pfr[index_max].is_end == 0)
            {
                *phdr_data_out = phdrd_compare;
                phdrd_compare = p_rec_data[index_max];
                pfr[index_max].is_end++;
                return 0;
            }
            res_rec_read[index_max] = pt_lpcap_read_frame_record(&pfr[index_max], &p_rec_data[index_max]);

            if (!res_rec_read[index_max])
                return -1;
            else
            {
                *res_hdrd = p_rec_data[index_max];
                *phdr_data_out = *res_hdrd;
                return 0;
            }
        }
        else
        {
            ;
        }

        int r_cmpp = rec_compare(&p_rec_data[index_max ? 0 : 1].pcp_rec_hdr, &phdrd_compare.pcp_rec_hdr);
        if (r_cmpp == -1)
        {
            index_max = index_max ? 0 : 1;
            *phdr_data_out = phdrd_compare;
            phdrd_compare = p_rec_data[index_max];
            return 0;
        }
        else
        {
            res_hdrd = &p_rec_data[index_max ? 0 : 1];
        }
    }
    *phdr_data_out = *res_hdrd;
   
    return 0;
}

 
long int pcap_files_merge_two(char *pcp_src_path1, char *pcp_src_path2, char *pcp_out_path)
{

    unsigned long count_out_packets = 0;
    PCAPFILE *pfr[2] = {NULL, NULL};

    pfr[0] = lpcap_open(pcp_src_path1);
    pfr[1] = lpcap_open(pcp_src_path2);

    if (pfr[0] == NULL || pfr[1] == NULL)
        return -1;

    pcap_hdr_t phdr[2];
    int r = lpcap_read_header(pfr[0], &phdr[0]);
    if (!r)
        return -1;
    r = lpcap_read_header(pfr[1], &phdr[1]);
    if (!r)
        return -2;

    PCAPFILE_TS_t pfr_ts[2];
    pfr_ts[0].f = pfr[0];
    pfr_ts[0].count_read = 0;
    pfr_ts[0].is_end = 0;

    pfr_ts[1].f = pfr[1];
    pfr_ts[1].count_read = 0;
    pfr_ts[1].is_end = 0;

    PCAPFILE *pfout = lpcap_create(pcp_out_path);
 
    int ret = 0;
    static pcaprec_hdr_and_data_t phdr_data_out;
    while ((ret = pck_get_next_abst(pfr_ts, &phdr_data_out)) != -1)
    {
        if (lpcap_write_pack(pfout, &phdr_data_out) == 0)
            break;
        count_out_packets++;
    }          
    lpcap_close_file(pfout);
    return count_out_packets;
}

char test_file_names[3][100]= 
{
"./pcaplibtestfile0.pcap" ,
"./pcaplibtestfile1.pcap" ,
"./pcaplibtestfile2.pcap" ,

};
char test_file_out[]= "./pout.pcap";
#define  PKTS_COUNT   50 
int test_count_packets[]={PKTS_COUNT, PKTS_COUNT/2,PKTS_COUNT/3};
int test_vals[]={0, 100,200};
int test_res_count[sizeof(test_count_packets)/sizeof(test_count_packets[0])]={0, 0,0};

int main(int argc, char **args)
{
    char in_f_paths[40][1024 * 10];
    char out_f_path[1024 * 10];
    int in_f_paths_len = argc - 2;
    unsigned long int count_result_packs = 0;
    int i = 0;

#ifdef    TCPMERGE_TEST
          printf("TESTING MODE");
          for(i = 0;i< sizeof(test_file_names)/sizeof(test_file_names[0]); i++)
          {
              memcpy(in_f_paths[i] ,test_file_names[i], sizeof(test_file_names[i]));
          }
          strcpy(out_f_path, test_file_out);
          in_f_paths_len = sizeof(test_file_names)/sizeof(test_file_names[0]);
          printf(" generate test data ...");
          gen_test();
          printf(" ok\n");
#else      
  
          
    if (argc == 1)
    {
        
        printf("\n\n\n\ttcpmerge  -  merge a several pcap files.\n\tUsing: tcpmerge path_of_file1 path_of_file2 path_of_file3 _path_of_out_file\n\n\n\n\n");
        return 0;
    }
    for (i = 1; i < argc - 1; i++)
    {
        strcpy(in_f_paths[i - 1], args[i]);
    }

    for (i = 0; i < in_f_paths_len; i++)
    {
        printf(" in_f_paths %s\n", in_f_paths[i]);
    }
   strcpy(out_f_path, args[argc - 1]);
#endif
   
    printf(" out_f_path %s\n", out_f_path);

    char first_file_p[1024 * 10];
    strcpy(first_file_p, in_f_paths[0]);


    //  цикл генерации последовательности для двойной подстановки  в формате
    // ( файл для смерживания 1, файл для смерживания 2 , результирующий)
    for (i = 1; i < in_f_paths_len; i++)
    {
        static char out_tmp[sizeof(out_f_path)];
        static char numbuf[4];
        snprintf(numbuf, sizeof(numbuf), "%d", i);
        memcpy(out_tmp, out_f_path, sizeof(out_f_path));
        if (i != (in_f_paths_len - 1))
        {
            strcat(out_tmp, numbuf);
        }

        //printf("=== in1 %s in_f_paths %s , out %s\n", first_file_p, in_f_paths[i], out_tmp);
        printf(" merge file %s...\n", in_f_paths[i]);

    
        long int code_merge = pcap_files_merge_two(first_file_p, in_f_paths[i], out_tmp);

        if (code_merge < 0)
        {
            switch (code_merge)
            {
            case -1:
                printf(" error open first input file (%s)\n", first_file_p);
                break;

            case -2:
                printf(" error open first input file(%s)\n", in_f_paths[i]);
                break;

            case -3:
                printf(" error open output file(%s)\n", out_tmp);
                break;
            }
            break;
        }
        else
        {
            count_result_packs += code_merge;
        }
        strcpy(first_file_p, out_tmp);
    }

    for (i = 1; i < in_f_paths_len; i++)
    {
        static char out_tmp[sizeof(out_f_path)];
        static char numbuf[4];
        snprintf(numbuf, sizeof(numbuf), "%d", i);
        memcpy(out_tmp, out_f_path, sizeof(out_f_path));
        strcat(out_tmp, numbuf);
        printf("\n remove %s \n", out_tmp);
        remove(out_tmp);
    }
    printf("\n finish ,   %li packets merged\n", count_result_packs);
#ifdef TCPMERGE_TEST
    printf(" TEST [exist all packets] ");
   int tr =  check_exists_data_out_file();
   if(tr) printf(" errors %d\n\n" , tr );
   else 
       printf("   Ok\n" );
#endif    
    return 0;
}


int gen_test()
{
  int i=0;
 
  const int udp_data_sz = 1440;// udp data size
 
  ethernet_data_t eda;
  eda.len = udp_data_sz +(sizeof(eth_frame_t)+sizeof(ip_packet_t))+8;//34 -  headers len

  uint8_t eth_data[eda.len];
  eth_frame_t * eth_f = (eth_frame_t *) eth_data;
  network_packet_frame_t npf;
  uint8_t  m_addr[] = {0xef,0xab,0x03, 0xdc,0xee,0x11};
  memcpy(npf.dst_mac ,m_addr , sizeof(m_addr));
//change mac
  m_addr[4] = 0x44;
  m_addr[5] = 0x88;

  memcpy(npf.src_mac ,m_addr , sizeof(m_addr));
  npf.src_port = 4567;
  npf.dst_port = 4568;
  strcpy(npf.src_ip, "192.168.23.100");
  strcpy(npf.dst_ip, "192.168.22.105");
  uint8_t tdata[ udp_data_sz ];
  npf.data = tdata;
  npf.data_len = sizeof(tdata);
  build_udp_frame(eth_f , &npf ); // convert network_packet_frame_t to  eth_frame_t
  eda.data = (void *) eth_f;
////////////////////////////////////////
  PCAPFILE * pfl = lpcap_create( test_file_names[0]);
  for( i=0;i< test_count_packets[0];i++ )
  {
   uint32_t ts_time =time(NULL);
      memset(tdata ,  test_vals[0]+i,sizeof(tdata));
       npf.src_port = 3;
      npf.dst_port = 3;
      build_udp_frame(eth_f , &npf ); // convert network_packet_frame_t to  eth_frame_t
      eda.data = (void *) eth_f;
   lpcap_write_data( pfl , &eda , ts_time +(uint32_t)i, i );
  }
  lpcap_close_file( pfl );


 
//////////////////////////////////////////
  pfl = lpcap_create(test_file_names[1]);
  for( i=0;i<test_count_packets[1];i++ )
  {
      uint32_t ts_time =time(NULL);
      memset(tdata , test_vals[1]+i,sizeof(tdata));
      npf.src_port = 2;
      npf.dst_port = 2;
      build_udp_frame(eth_f , &npf ); // convert network_packet_frame_t to  eth_frame_t
      eda.data = (void *) eth_f;
      lpcap_write_data( pfl , &eda , ts_time +(uint32_t)i ,(uint32_t)i);
  }
  lpcap_close_file( pfl );
/////////////////////////////////////////////

//////////////////////////////////////////
  pfl = lpcap_create(test_file_names[2]);
  for( i=0;i< test_count_packets[2];i++ )
  {
      uint32_t ts_time =time(NULL);
      memset(tdata ,test_vals[2]+i ,sizeof(tdata));
      npf.src_port = 1;
      npf.dst_port = 1;
      build_udp_frame(eth_f , &npf ); // convert network_packet_frame_t to  eth_frame_t
      eda.data = (void *) eth_f;
      lpcap_write_data( pfl , &eda , ts_time +(uint32_t)i ,(uint32_t)i);
  }
  lpcap_close_file( pfl );
/////////////////////////////////////  

#if 0
  PCAPFILE  * pfr = lpcap_open("./pcaplibtestfile.pcap");
  pcap_hdr_t   phdr;
  if( lpcap_read_header( pfr, &phdr ))
  {
    print_hdr(&phdr);
    int rese_rec_read = 0 ;
    pcaprec_hdr_and_data_t  p_rec_data;
    do{   
       rese_rec_read = lpcap_read_frame_record( pfr , &p_rec_data);
       print_rec_hdr( &p_rec_data.pcp_rec_hdr);
    }while(rese_rec_read>0);
  } 
#endif
 return 0;
}

int check_exists_data_out_file() // check contained all data
{

  int num_file = 0;
  int i = 0;
  int cnt_fl = sizeof(test_file_names)/sizeof(test_file_names[0]);
  for(num_file = 0; num_file < cnt_fl; num_file++)
  {
   PCAPFILE  * pfr = lpcap_open(test_file_out);
   pcap_hdr_t   phdr;
   if( lpcap_read_header( pfr, &phdr ))
   {
  // print_hdr(&phdr);
     int rese_rec_read = 0 ;
      int val = test_vals[num_file];
     pcaprec_hdr_and_data_t  p_rec_data;
     do{   
       rese_rec_read = lpcap_read_frame_record( pfr , &p_rec_data);
       int finded_pos = -10;
       eth_frame_t * eth_f = (eth_frame_t *)  p_rec_data.packet_data;
        ip_packet_t *ip_f = (ip_packet_t *)eth_f->data;
       udp_packet_t *udpp = (udp_packet_t * ) ip_f->data;
       
      
       int count_success = 0;
       short sz =  htons(udpp->len) -8;
       for(i=0;i<sz;i++ )
       {
           uint8_t  ch_data= udpp->data[i];
          // if(   (test_vals[num_file]) <=  ch_data  &&   (test_vals[num_file]+test_count_packets[num_file]) >=ch_data )
           if(test_vals[num_file]+ test_res_count[num_file] == ch_data)
           {
              count_success++;
           } 
          else 
              break;
       }
       if( count_success==0)  continue;
       else
       {
           if( count_success==  sz )
               test_res_count[num_file]++;
               
       }
       val++;
       //print_rec_hdr( &p_rec_data.pcp_rec_hdr);
      }while(rese_rec_read>0);
      lpcap_close_file(pfr);
   } else return -1 * num_file;  
     
  }
  int oktest = -1;
   for(i=0;i < sizeof(test_count_packets)/sizeof(test_count_packets[0]);i++ )
   {
     if(test_res_count[i] == test_count_packets[i])
     {
        oktest = 0; 
     }
     else
     {
         oktest = -i;
     }
   }
  
  return oktest; 
}
 
