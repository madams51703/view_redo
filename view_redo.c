#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>

int do_16_byte_xor(unsigned char *block1, unsigned char *block2, unsigned char *out);
int do_checksum(int block_size, unsigned char *buffer);



int main(int argc, char *argv[]){
int count;
int block_offset;
int err;
int fd;
int ascii;
long redo_record_length;
char *ptr;
const unsigned char * pc ;
struct stat statbuf;
const char *filepath ;
int checksum_result;
long blocks_processed = 0;
int found_changes =0;

    if(argc < 2){
        printf("File path not mentioned\n");
        exit(0);
    }
   
    filepath = argv[1];
    fd = open(filepath, O_RDONLY);
    if(fd < 0){
        printf("\n\"%s \" could not open\n",
               filepath);
        exit(1);
    }

    err = fstat(fd, &statbuf);
    if(err < 0){
        printf("\n\"%s \" could not open\n",
                       filepath);
        exit(2);
    }

    ptr = mmap(NULL,statbuf.st_size,
            PROT_READ|PROT_WRITE,MAP_PRIVATE,
            fd,0);
    if(ptr == MAP_FAILED){
        printf("Mapping Failed\n");
        return 1;
    }
    close(fd);
    pc=ptr;

	if ( pc[1] == 0x22 )
	{
		printf("We found a redo log\n");
	}
	else
	{
		printf("This is not a redo log\n");
		exit (1);
	}
	
	for ( count=0; count < statbuf.st_size; count++)
	{
		if ( pc[count] == 0x01 & pc[count+1] == 0x22 )
		{
			blocks_processed++;
			printf("Found Block Signature at %ld (%06x)\n",count,count);
			printf("RBA(Redo Block Address) 0x%02X%02X%02X%02X.%02X%02X%02X%02X\n",pc[count+0xb],pc[count+0xb-1],pc[count+0xb-2],pc[count+0xb-3],pc[count+0x8],pc[count+0x8-1],pc[count+0x8-2],pc[count+0x8-3] );
			printf("This is redo block %ld\n", blocks_processed);
    			checksum_result=do_checksum(512,(unsigned char *) (pc+count ) ) ;
			if ( (count % 512 ) == 0 )
			{
    				printf("Checksum Check: %04X\n",checksum_result );
				if (checksum_result != 0 )
				{
					printf("BAD CHECKSUM\n");
					exit(1);
				}
			}
			else
			{
				printf("Checksum Check: Not a block boundary\n");
			}

			if ( pc[count+0x14] == 0 )
			{
				printf("VLD:%02X\n",pc[count+0x14] );
				printf("Redo Block is not valid as VLD is zero\n");
			}	

			if ( pc[count+0x14] > 0x20 )
			{
				printf("VLD(Larger header):%02X\n",pc[count+0x40] );	
			}
			else
			{
				printf("VLD:%02X\n",pc[count+0x14] );
			}

			if ((pc[count+0x14] & 0x1) ==0x1 )
			{
				printf("Found Change Vector(s)\n");	
			}
			printf("Sequence number:%ld\n",pc[count+0x08] + (pc[count+0x08+1]*256) + (pc[count+0x08+2]*65536) + (pc[count+0x08+3]*16777216) );
			if (pc[count+0x0C] == 0x10 )
			{
				printf("Offset:%02X ",pc[count+0x0C] );
			}
			else
			{
				printf("Offset:%02X\n",pc[count+0x0C] );
			}

//			Always do this now that we know about the 2 record headers
			if (pc[count+0x0C] != 0x00 )
			{
				printf("\n%02X\n", pc[count+0x0C]  );
				printf("Redo Record Length: %02X %02X ",(pc[count + pc[count+0x0C] +1 ] ), (  pc[count + pc[count+0xc] ] ) );
				redo_record_length = (pc[count + pc[count+0x0C] ] )+ (  pc[count + pc[count+0xc]+1 ] *256) ;
//				printf("Redo Record Length: %ld ",(pc[count + pc[count+0x0C] ] )+ (  pc[count + pc[count+0xc]+1 ] *256) );
				printf("Opcode: %d.%d\n",pc[count+84],pc[count+85]);
				printf("Redo record spans %ld to %ld",count, count+redo_record_length);	
				
				for ( block_offset=0 ; block_offset < redo_record_length ; block_offset++ )
				{
					if ( pc[count + 0x14] == 0 )
					{
						// Breaking because redo record is not Valid
						break;
					}

					if ( (block_offset % 16) == 0 )
					{

						if (block_offset != 0)
						{

							for ( ascii = 16 ; ascii >=0 ; ascii -- )
							{
								if (isprint(pc[count+block_offset-ascii]) != 0 )
								{ 
									printf("%c",pc[count+block_offset-ascii] );
								}
								else
								{
									printf(" ");
								}	

							}	
						}

						printf("\n%04X: ",block_offset);
					}

					printf("%02X ",pc[count+block_offset] );
				}
				printf("\n");
			}
			else
			{

				printf("Offset is zero, last record in block\n");
				
			}
		}
	}
	
/*
    ssize_t n = write(1,ptr,statbuf.st_size);
    if(n != statbuf.st_size){
        printf("Write failed");
    }

*/ 

    err = munmap(ptr, statbuf.st_size);

    if(err != 0){
        printf("UnMapping Failed\n");
        return 1;
    }
    return 0;
}



#include <stdio.h>
#include <strings.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


int do_checksum(int block_size, unsigned char *buffer)
{
 unsigned char block1[16]="";
 unsigned char block2[16]="";
 unsigned char block3[16]="";
 unsigned char block4[16]="";
 unsigned char out1[16]="";
 unsigned char out2[16]="";
 unsigned char res[16]="";
 unsigned char nul[16]="";
 int count = 0;
 unsigned int r0=0,r1=0,r2=0,r3=0,r4=0;

 while(count < block_size)
 {
 memmove(block1,&buffer[count],16);
 memmove(block2,&buffer[count+16],16);
 memmove(block3,&buffer[count+32],16);
 memmove(block4,&buffer[count+48],16);
 do_16_byte_xor(block1,block2,out1);
 do_16_byte_xor(block3,block4,out2);
 do_16_byte_xor(nul,out1,res);
 memmove(nul,res,16);
 do_16_byte_xor(nul,out2,res);
 memmove(nul,res,16);
 count = count + 64;
 }
 memmove(&r1,&res[0],4);
 memmove(&r2,&res[4],4);
 memmove(&r3,&res[8],4);
 memmove(&r4,&res[12],4);
 r0 = r0 ^ r1;
 r0 = r0 ^ r2;
 r0 = r0 ^ r3;
 r0 = r0 ^ r4;
 r1 = r0;
 r0 = r0 >> 16;
 r0 = r0 ^ r1;
 r0 = r0 & 0xFFFF;
 return r0;
}
int do_16_byte_xor(unsigned char *block1, unsigned char *block2, unsigned char *out)
{
 int c = 0;
 while (c<16)
 {
 out[c] = block1[c] ^ block2[c];
 c ++;
 }
 return 0;
}



