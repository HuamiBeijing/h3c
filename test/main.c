#include <stdio.h>
#include "hbeaconservice.h"
#include "json-c/json.h"
#include <curl/curl.h>
#include <time.h>

#include <unistd.h>


//#define USER "gd2dtzKljMmLUTVNWgA6"  
//#define PSW "tdH1VauNj&Dt>gKhU*Axb5LrwGg*n6czRVWHqCH_O9mdUFf8xDewAlWnBYyc"  

#define USER "gE1nm7Pzq0U5U1UnawIa"
#define PSW  "_P>U4YO085LQvkWPQG2mYw9*w6oK5JBTOmLZkQXb9YLNYXO4G<tN4q*IfKuy" 

HBeaconStatus setup(uint8_t len,
		    uint8_t scannerId[len])
{
  printf("%d\t%s\n", len, scannerId);
  HBeaconStatus status = {
    .code = HBeaconStatusOk,
    .message = {[0 ... 63] = 'a'},
  };

  return status;
}




HBeaconStatus process(uint8_t len1,
		      uint8_t scannerId[],
		      HBeaconAdvPacketType type,
		      uint8_t dataLen,
		      uint8_t rawData[dataLen],
		      uint8_t rssiValue)
{


  printf("%02x\n", rssiValue);
  printf("-----------------------------\n");




  HBeaconStatus status = {
    .code = HBeaconStatusOk,
    .message = {[0 ... 63] = 'b',},
  };





  return status;
}

int main()
{


  printf("==============THIS IS A TEST CASE===============\n\n");
  HBeaconScanService service;

  uint8_t user[] = USER;
  uint8_t passwd[] = PSW;

  HBeaconStatus status = HBeaconScanServiceInit(&service, sizeof(user), user, sizeof(passwd), passwd);
  printf("service init code:\t%d\tmessage:%s\n\n",status.code,status.message);

   
  uint8_t rawData[20] = {0x05,0x09,0x4d,0x49,0x31,0x53,0x05,0x02,0xe0,0xfe,0xe7,0xfe,0x07,0x16,0xe0,0xfe,0xc3,0x16,0x00,0x00};
  //uint8_t scannerId[8] = { 0x05,0x02,0xff,0xee,0xee,0xff,0xff,0xff };
  uint8_t *scannerId = "210235A1PRC161000536-1";

 

  uint8_t macAddr[6] = {0x88,0x0f,0x10,0xeb,0xc1,0xc9};
  uint8_t h3cmac[6] = {0xc8,0x0f,0x10,0x47,0x19,0xa3};
  
    
  
  HBeaconStatus s = service.configureScanner(HBeaconScannerSetup, strlen(scannerId), scannerId);
  printf("configures:\t%s\n\n",s.message);
  
  uint32_t count = 0;

  while(1)
    {
  HBeaconStatus ss = service.processPacket(strlen(scannerId), scannerId, HBeaconScanRspDataType,h3cmac,20, rawData, 0xee);
  printf("processpacket code:\t%d\tmessage:\t%s\n\n",ss.code, ss.message);
         
  printf("==============Mac address change to error state\n");
  uint8_t macAddr2[6] = {0x88,0x0f,0x10,0xeb,0xc1,0xc7};
  HBeaconStatus sss  = service.processPacket(strlen(scannerId), scannerId, HBeaconScanRspDataType,macAddr2,20, rawData, 0xee);
  printf("processpacket code:\t%d\tmessage:\t%s\n\n", sss.code,sss.message);

  uint8_t macaaa[6] = {0x8f,0x0f,0x10,0xeb,0xc1,0xc5};
  sss  = service.processPacket(strlen(scannerId), scannerId, HBeaconScanRspDataType,macaaa,20, rawData, 0xee);
  printf("processpacket code:\t%d\tmessage:\t%s\n\n", sss.code,sss.message);
  
  sleep(1);
  if(count ==15) break;
  count++;
    }

  printf("==================rawdata change to error format\n");
  uint8_t rawData2[20] = {0x05,0x09,0x4d,0x49,0x31,0x53,0x05,0x02,0xe0,0xff,0xe7,0xfe,0x07,0x16,0xe0,0xfe,0xc3,0x16,0x00,0x00};
  HBeaconStatus ssss = service.processPacket(strlen(scannerId), scannerId, HBeaconScanRspDataType,macAddr,20, rawData2, 0xee);
  printf("processpacket code:\t%d\tmessage:\t%s\n\n",ssss.code, ssss.message);
  

  printf("=================Add scanner ID\n"); 
  uint8_t *sid1 = "askdfajsdfklafsadf";
  status = service.configureScanner(HBeaconScannerSetup, strlen(sid1), sid1);
  printf("Add scanner:%d\t%s\n\n",status.code,status.message);


  
  printf("=================Add scanner ID\n");
  uint8_t *sid2 = "foqwfsjkfjasfdjas";
  status = service.configureScanner(HBeaconScannerSetup, strlen(sid2),sid2);
  printf("Add scanner:%d\t%s\n\n",status.code,status.message);
  

  printf("==============process packet with another scanner ID\n");
  status = service.processPacket(strlen(sid1), sid1, HBeaconScanRspDataType,macAddr,20, rawData, 0xee);
  printf("%s\n\n", status.message);

  printf("==============Remove scannner ID\n");
  status = service.configureScanner(HBeaconScannerRemove, strlen(sid1), sid1);
  printf("%s\n\n", status.message);

  
  printf("=============After remove process packet\n");
  status = service.processPacket(strlen(sid1), sid1, HBeaconScanRspDataType,macAddr,20, rawData, 0xee);
  printf("%s\n\n", status.message);
  
  
  status = HBeaconScanServiceShutdown(&service);
  printf("============%s\n",status.message);
  return 0;
}
