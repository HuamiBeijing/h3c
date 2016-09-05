/**
****************************************************************************************
*
* @file hbeaconscanservice.c
*
* @brief hbeacon scan service implementation
*
* Copyright (C) Huami  2016
*
* VERSION:1.5
****************************************************************************************
*/


/*
 * INCLUDE FILES
 ****************************************************************************************
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#ifdef CROSS
#include <json/json.h>
#else
#include <json-c/json.h>
#endif
#include <curl/curl.h>
#include "uthash.h"
#include "utlist.h"
#include "hbeaconservice.h"
#include <time.h>
#include <string.h>


/*
 * DEFINES
 ****************************************************************************************
 */
#define TEST 0
#define DEBUG 0

#if TEST
#define HURL url // "https://api-test-beacon.huami-inc.com/hbox/838ffee8843/opEvents"
#else
#define DEBUG 0
#define HURL url
#endif
#if DEBUG
#define hbprintf printf
#else
#define hbprintf
#endif

#define BL_CLEANUP_TIME  (7200)  // two hours

#define JSON_CACHE_LEN  (20)

#ifndef JSON_CACHE_TIME
#define JSON_CACHE_TIME (5)
#endif
 
/*
 * GLOBAL VARIABLE DEFINITIONS
 ****************************************************************************************
 */

static const char* _hc_url = "https://api-beacon.huami-inc.com/hbox/";
static const char* _hc_action = "/opEvents";

static uint8_t *_username = NULL;
static uint8_t *_password = NULL;

static uint8_t isPasswdValid = 1;

static uint32_t TimesTamp = 0;
static uint32_t CacheTime =0;

static struct json_object *Cache_json_data = NULL; 
/*
 * STRUCTURES
 ****************************************************************************************
 */


//black list structure
typedef struct _blacklist_element {
  uint8_t device[6];
  struct _blacklist_element *prev;
  struct _blacklist_element *next;
} BlacklistElement;

//scanner list structure 
typedef struct _scannerlist_element{
	uint8_t *scanner;
	uint8_t scannerlen;
	CURL *curl;
	uint8_t  macSent[6];
  struct _scannerlist_element *prev;
  struct _scannerlist_element *next;
} ScannerlistElement;



// black list and scanner list  cache list instance 
static BlacklistElement *_blacklist = NULL;
static BlacklistElement *_cachelist = NULL;
static ScannerlistElement *_scannerlist = NULL;


typedef struct _packdata{
	HBeaconAdvPacketType type;

	uint8_t scannerIdlen;
	uint8_t *scannerId;

	uint8_t mac_len;
	uint8_t *mac;

	uint8_t dataLen;
	uint8_t *rawData;

	int rssi;
} Packdata;


typedef struct _unpackdata
{
  struct json_object * mac;
  struct json_object * huamiid;
  struct json_object * deviceId;
  struct json_object * type;
}  Unpackdata;



/*
 * PRIVATE FUNCTION DEFINITIONS
 ****************************************************************************************
 */


/**
 ****************************************************************************************
 * @brief Convert uint8 number to HEX string.
 * @param[in] pbDest pointer to return string.
 * @param[in] pbSrc pointer to uint8 number.
 * @param[in] offset pbSrc's offset to write.
 * @param[in] nLen number to write.
 * @return none.
 ****************************************************************************************
 */
static void hexToStr(uint8_t *pbDest,uint8_t *pbSrc,int offset, int nLen)
{
	uint8_t	ddl,ddh;
	int i;
	for (i=0; i<nLen; i++)
	{
	  ddh = 48 + pbSrc[i+offset] / 16;
	  ddl = 48 + pbSrc[i+offset] % 16;
	  if (ddh > 57) ddh = ddh + 39;
	  if (ddl > 57) ddl = ddl + 39;
	  pbDest[i*2] = ddh;
	  pbDest[i*2+1] = ddl;
	}
	pbDest[nLen*2] = '\0';
}


static void strToHex(uint8_t *pbDest, uint8_t *pbSrc,int offset,int nLen)
{
  uint8_t h1,h2,s1,s2;
  int i;
  
  for (i=0; i<nLen; i++)
    {
      h1 = pbSrc[2*i+offset];
      h2 = pbSrc[2*i+1+offset];

      s1 = toupper(h1) - 0x30;
      if (s1 > 9)
	s1 -= 7;

      s2 = toupper(h2) - 0x30;
      if (s2 > 9)
	s2 -= 7;

      pbDest[i] = s1*16 + s2;
    }
}

/**
 ****************************************************************************************
 * @brief MAC string compare function.use to compare algorithm.
 * @param[in] black list device string a.
 * @param[in] black list device string b.
 * @return if a==b return 0.
 ****************************************************************************************
 **/

static int _mac_cmp(BlacklistElement *a, BlacklistElement *b)
{
  return memcmp(a->device, b->device, 6); //TODO: macAddress length is 6;
}

static int _id_cmp(ScannerlistElement *a, ScannerlistElement *b)
{ 
  return memcmp(a->scanner, b->scanner, b->scannerlen);
}



/**
****************************************************************************************
* @brief scanner list  search function
* @param[in] scanner list id 
* @param[in] scanner list element pointer 
* @return void
****************************************************************************************
**/

static void scannerlistSearch(uint8_t *scannerId,uint8_t len,ScannerlistElement** t)
{

  ScannerlistElement  *temp, search;
  search.scanner = malloc(len);
  search.scannerlen = len;
  memcpy(search.scanner,scannerId,len);
  DL_SEARCH(_scannerlist,temp,&search,_id_cmp);
  free(search.scanner);
  
  *t = temp;
} 

/**
 ****************************************************************************************
 * @brief black list add function.
 * @param[in] mac string .
 * @return instance count in black list.
 ****************************************************************************************
 */
static int blacklistAdd(BlacklistElement **bl,uint8_t *mac)
{
	BlacklistElement *dev,*temp;
	int count = 0;

	dev = (BlacklistElement *)malloc(sizeof(BlacklistElement));
	if(dev == NULL) return -1;
	memcpy(dev->device,mac,6);
	// add device instance to the black list
	DL_APPEND(*bl, dev);
	// return count of balck list
	DL_COUNT(*bl, temp, count);
	return 	count;
}

/**
 ****************************************************************************************
 * @brief black list search function.
 * @param[in] mac string .
 * @return if mac string instance exit in black list,return 1.
 ****************************************************************************************
 */
static int blacklistSearch(BlacklistElement **blacklist,uint8_t *mac)
{
	BlacklistElement *temp, search;
	memcpy(&search.device,mac,6);
	//search
	DL_SEARCH(*blacklist,temp,&search,_mac_cmp);
	if(temp) return 1;
	else  return 0;
}


static int blacklistCount(BlacklistElement **blacklist)
{
  BlacklistElement *dev,*temp;
  int count = 0;
  DL_COUNT(*blacklist, temp, count);
  return  count;
}

/**
****************************************************************************************
* @brief black list clean up function
* @param void
* @return void
****************************************************************************************
*/
static int blacklistCleanup(BlacklistElement **blacklist)
{

  //TODO: cleanup the black list
  BlacklistElement *bl_elem, *bl_tmp;
  DL_FOREACH_SAFE(*blacklist, bl_elem, bl_tmp) {
    DL_DELETE(*blacklist, bl_elem);
    free(bl_elem);
  }
  hbprintf("[ list cleanup]\n");
  return 0;
}


/**
 ****************************************************************************************
 * @brief resolve the advertising data.
 * @param[in] rawdata of the advertising.
 * @param[in] length of rawdata.
 * @param[in] advertising type of rawdata.
 * @return a pointer of advertising length.
 ****************************************************************************************
 */
static uint8_t* unpackAdv(uint8_t len, uint8_t rawdata[len], uint8_t type)
{
        uint8_t i=0, length =0,flag;
	do
	{
	  //printf("%d\t%02x\n", __LINE__, i);
		length = rawdata[i];
		flag = rawdata[i+1];
		if(length>0 && type == flag)
		  {
		    hbprintf("[rawdata length:%d , type: %x]\n",length,flag);
		    return rawdata + i;
		  }
		i = i+length+1;
	}while(i < len);
	return NULL;
}


//get return status function 
static HBeaconStatus getStatus(uint8_t code, uint8_t* msg)
{
    HBeaconStatus status = {
    .code = code,
    .message = "[SUCCESS]\0",
  };
  memcpy(status.message, msg, strlen(msg));
  return status;
}



/**
 ****************************************************************************************
 * @brief pack data to a json object .
 * @param[in] struct of json data.
 * @param[in] return string object data.
 * @return struct of json object.
 ****************************************************************************************
 */
static HBeaconStatus packJson(Packdata* pdata, uint8_t **obj)
{

  //timestamp
  time_t timestamp;
  uint8_t eveid[24], m[pdata->mac_len*2+1] , message[64];
  int status = 0 ;
  uint32_t steps = 0;
  HBeaconAdvPacketType type;
  uint8_t* scannerId;
  uint8_t* mac;
  uint8_t* rawData;
  struct json_object *json,*data_obj ,*adver,*adver_obj;

  if(pdata ==NULL)  return getStatus(HBeaconStatusError,"NULL pointer ");

  type  = pdata->type;
  mac = pdata->mac;
  scannerId = pdata->scannerId;
  rawData = pdata->rawData;


  //search black list ,if mac in blacklist ,return a error ,stop send to server.
  if(blacklistSearch(&_blacklist,mac))
  {
    hbprintf("[device found in black list cancel send]:%x%x%x%x%x%x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
 	  return getStatus(HBeaconStatusErrorBlacklist,"BLE device not registered");
  }

  hbprintf("[device not found in black list]\n");
  
  //get the steps information
  if(type == HBeaconScanRspDataType)
  {
    uint8_t *ser = unpackAdv(pdata->dataLen,rawData,0x02);
    if(ser == NULL) return getStatus(HBeaconStatusError,"Response data format error!");

    if(!(ser[2] == 0xe0 && ser[3] == 0xfe && ser[4] == 0xe7 && ser[5] == 0xfe))
      return getStatus(HBeaconStatusError,"Response data format error!");

    uint8_t *da = unpackAdv(pdata->dataLen,rawData,0x16);
    if(da == NULL) return getStatus(HBeaconStatusError,"Response data format error");

    steps = steps|(da[4]<<0);
    steps = steps|(da[5]<<8);
    steps = steps|(da[6]<<16);
    steps = steps|(da[7]<<24);
    if( steps< 0)
    {
        return getStatus(HBeaconStatusError,"Response data format error");
    }
    hbprintf("[packed steps]  :%d\n",steps);
  }


  json = json_object_new_object();
  data_obj = json_object_new_object();
  adver = json_object_new_array();
  adver_obj = json_object_new_object();
  if(json==NULL||adver==NULL)
  {
	  return getStatus(HBeaconStatusError,"NULL pointer");
  }

  // init the cache data array
  if(Cache_json_data == NULL)
    Cache_json_data = json_object_new_array();

  time(&timestamp); //get the timestamp 

  //cleanup black list every 2 hours 
  if(timestamp - TimesTamp >= BL_CLEANUP_TIME)
  {
	hbprintf("[black list clean up \n]");
	blacklistCleanup(&_blacklist);
	TimesTamp =timestamp;
  }	

  
  //convert mac to hex string
  hexToStr(m,mac,0,pdata->mac_len);

  // add the mac address to the cache list
  //when callback,which mac not in the cache list
  //it is a black device 
  if(!blacklistSearch(&_cachelist,mac))
  {
    int c =blacklistAdd(&_cachelist,mac);
    hbprintf("[mac add to cache list]:\t%d\n",c);
  }

  sprintf(eveid,"%s_%d",m,timestamp);
  json_object_object_add(json,"type",json_object_new_string("swipe"));
  json_object_object_add(json,"eventId",json_object_new_string(eveid));

  json_object_object_add(data_obj,"scanner",json_object_new_string(scannerId));
  json_object_object_add(adver_obj,"mac",json_object_new_string(m));

  if(type == HBeaconScanRspDataType)
  {
    sprintf(message,"{\"step\":\"%d\",\"rssi\":\"%d\"}",steps,pdata->rssi);
    json_object_object_add(adver_obj,"message",json_object_new_string(message));
  }

  json_object_object_add(adver_obj,"timestamp",json_object_new_int(timestamp));

  json_object_array_add(adver,adver_obj);

  json_object_object_add(data_obj,"advertiser",adver);
  json_object_array_add(Cache_json_data,data_obj);


  //
#if 1
  if(CacheTime == 0) CacheTime = timestamp;
  if(timestamp-CacheTime < JSON_CACHE_TIME)
  {
    return getStatus(HBeaconStatusDataCached,"[Cached]");
  } 
#endif
  
#if 0
  if(json_object_array_length(Cache_json_data) < JSON_CACHE_LEN)
    return getStatus(HBeaconStatusDataCached,"Cached data!");
#endif

  
  json_object_object_add(json,"data",Cache_json_data);
  
  //hbprintf("[pack json object]  :%s\n",json_object_to_json_string(json));
  uint8_t *backaaa = malloc(strlen(json_object_to_json_string(json)));
  backaaa= json_object_to_json_string(json);
  *obj = backaaa;


  json_object_put(Cache_json_data); 
  Cache_json_data = NULL;

  return getStatus(HBeaconStatusOk,"");
}


/**
 ****************************************************************************************
 * @brief unpack json data return form server.
 * @param[in] struct of json data.
 * @param[in] scannerid search and add black list.
 * @return -1 if error occur.
 ****************************************************************************************
 */
static int unpackJson(uint8_t* data,BlacklistElement *cachelist)
{
  int length =0  ,status = 0;
  struct json_object *json,*device,*dev_obj,*mac,*details,*huamiid,*deviceid,*type;
  uint8_t *unauth ="401";

  
  json = json_tokener_parse(data);
  device = json_object_object_get(json,"devices");
  if(device != NULL)
  {
    length = json_object_array_length(device);
    hbprintf("[call back device count]:\t%d\n",length);
    if(length == blacklistCount(&_cachelist))  // if send cached length == back cached length ,means no black device  
      {
	hbprintf("[receive cache mac len = cache list count =%d , no black device]\n",length);
	return 0;
      }
    
    uint8_t mm[length][6];
    for(int i=0; i<length; i++)
    {
      dev_obj=  json_object_array_get_idx(device,i);
      mac =  json_object_object_get(dev_obj, "mac");
      if(mac == NULL)
      {
	hbprintf("[call back return MAC NULL]\n");
	return 0;
      }
      hbprintf("[call back device mac]:\t%s\n",json_object_to_json_string(mac));
      uint8_t *macstr = json_object_to_json_string(mac);
      strToHex(mm[i],macstr,1,6);//offset set to 1,because first char is:"  
    }

    //check cached mac list and back mac,
    //if cache list mac not  back form server
    //means it is a black device ,add to black list 
    BlacklistElement *elt;
    DL_FOREACH(_cachelist,elt)
    {
      int found =0;
      for(int i=0; i<length; i++)
	{
	  if(!memcmp(elt->device,mm[i],6))
	    found=1;
	}

      if(!found)
      {
	//add to the black list
	if(!blacklistSearch(&_blacklist,elt->device))
	  {
	    hbprintf("[add to black list]:\t %x%x%x%x%x%x\n",elt->device[0],elt->device[1],elt->device[2],elt->device[3],elt->device[4],elt->device[5]);
	    blacklistAdd(&_blacklist,elt->device);
	  }
	
      }else
	{
	  hbprintf("[not add to black list]\n");
	}
    }

    
  }else
  {
	    //if error happeded , like no authentication
	    struct json_object *error_status = json_object_object_get(json,"status");
	    struct json_object *error_error = json_object_object_get(json,"error");
	    //if return json status message = 401 means no authentication,make ispasswdvalid = 0
	    if(!strcmp(json_object_to_json_string(error_status),unauth))
	    {
	      hbprintf("[username or passwd error]\n");
	      isPasswdValid = 0;
	    }
	    hbprintf("[call back error reason]  :%s:%s\n",json_object_to_json_string(error_status),json_object_to_json_string(error_error));
    }

  
  return status;
}

/**
 ****************************************************************************************
 * @brief callback function of curl send data.
 * @param[in] ptr server write data pointer.
 * @param[in] size .
 * @param[in] nmemb size of write data.
 * @param[in] userp.
 * @return must return write data size.
 ****************************************************************************************
 */
static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
    hbprintf("[write call back size]  :%d\n",nmemb);
    hbprintf("[write call back data]  :%s\n",ptr);
    //unpack the server write data. userp pinter to mac address 
    unpackJson(ptr,(BlacklistElement *)userp);

    return nmemb;
}



/**
 ****************************************************************************************
 * @brief set up scanner
 * @return .
 ****************************************************************************************
 */

/*
 * setupScannerInternal
 * add scannerId into the service
 * todo: should we also provide the remove action?
 */

static HBeaconStatus setupScannerInternal(uint8_t len,
					  uint8_t scannerId[len])
{


  ScannerlistElement* temp;
  scannerlistSearch(scannerId,len,&temp);
  if (temp) {
    return getStatus(HBeaconStatusError,"Scanner already exists");
  }

  // add scanner id to a list , fill curl and len 
  ScannerlistElement *s = (ScannerlistElement *)malloc(sizeof(ScannerlistElement));
  if(s == NULL) return getStatus(HBeaconStatusError,"NULL pointer");
  s->scanner = malloc(len);
  memcpy(s->scanner,scannerId,len);
  s->curl = curl_easy_init();   
  s->scannerlen = len;
  DL_APPEND(_scannerlist, s);
  
  return getStatus(HBeaconStatusOk,"Scanner registered successfully!");
}


// remove setup function 
static HBeaconStatus removeScannerInternal(uint8_t len,
				   uint8_t scannerId[len])
{


  ScannerlistElement* temp;
  scannerlistSearch(scannerId,len,&temp);
  if(temp)
    {
      free(temp->scanner);
      curl_easy_cleanup(temp->curl);
      DL_DELETE(_scannerlist,temp);
   
      return getStatus(HBeaconStatusOk,"Remove scanner!");
   }else
   {
      return getStatus(HBeaconStatusError,"Scanner not found!");
   }

}

// service configuretion 
static HBeaconStatus configureScannerInternal(HBeaconScannerAction action,
 					      uint8_t length,
					      uint8_t scannerID[length])
{

  if (action == HBeaconScannerSetup)
    return setupScannerInternal(length, scannerID);
  else
    return removeScannerInternal(length, scannerID);
}


/**
 ****************************************************************************************
 * @brief process advertising packet data and send to server
 * @param[in] scanner id length.
 * @param[in] scanner id data.
 * @param[in] advertising type.
 * @param[in] mac address data.
 * @param[in] raw data len
 * @param[in] raw data
 * @param[in] rssi value
 * @return  status.
 ****************************************************************************************
 */
static HBeaconStatus processPacketInternal(uint8_t scannerIdlen,
				   uint8_t scannerId[scannerIdlen],
				   HBeaconAdvPacketType type,
				   uint8_t macAddr[6],
				   uint8_t dataLen,
				   uint8_t rawData[dataLen],
				   int rssiValue)
{

   uint8_t *fields;
   int httpCode;
   CURL *curl;
   CURLcode res;
   struct curl_slist *slist = NULL;
   struct json_object *json = NULL;

   HBeaconStatus status;

   // pack the data to a pack struct
   Packdata pack = {
      .scannerId = scannerId,
      .scannerIdlen =scannerIdlen,
      .mac = macAddr,
      .mac_len = 6,
      .dataLen = dataLen,
      .rawData = rawData,
      .type = type,
      .rssi = rssiValue,
   };


   if(!isPasswdValid)
   {
     hbprintf("[pass invalid]");
     return getStatus(HBeaconStatusErrorLicense,"License error!");
   }


   ScannerlistElement *temp;
   scannerlistSearch(scannerId,scannerIdlen,&temp);
   if(!temp)
   {
     return getStatus(HBeaconStatusError,"Scanner not registered");
   }

   status = packJson(&pack,&fields);
   if(status.code != HBeaconStatusOk)
   {
        hbprintf("[pack json return error!]\n");
        return status;
   }

   curl = temp->curl;
   if (curl) {
     
     hbprintf("[curl send json data]  :\n%s \n\n",fields);
     uint8_t url[128];
     sprintf(url,"%s%s%s",_hc_url,scannerId,_hc_action);
     curl_easy_setopt(curl, CURLOPT_URL, HURL);
     hbprintf("[curl send url]  :%s\n",HURL);

     curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L);

     slist = curl_slist_append(NULL,"Content-Type:application/json;charset=UTF-8");
     curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
     curl_easy_setopt(curl, CURLOPT_TIMEOUT,2);

     curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields); //set curl json data string
     curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);

     curl_easy_setopt(curl, CURLOPT_USERNAME, _username);//set curl username and password
     curl_easy_setopt(curl, CURLOPT_PASSWORD, _password);
     
     hbprintf("[username]  :%s\n[passwd]  :%s\n",_username,_password);


     curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);//set the server write callback function
     curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)_cachelist);

     res = curl_easy_perform(curl);//perform the curl transfer
     free(fields);
     time(&CacheTime);
     blacklistCleanup(&_cachelist);
     hbprintf("[perform back ]:\t%d\n",res);
     if (res != CURLE_OK)
     {
         return getStatus(HBeaconStatusError,"Network failed");
     }
      
	//get the http send info , if send success ,return 200
     int return_code = curl_easy_getinfo(curl,  CURLINFO_RESPONSE_CODE , &httpCode);

	if(return_code ==CURLE_OK)
  	{
  	  hbprintf("[http response code] :\t%d\n",httpCode);
	  if(httpCode != 200)
    	  {
           return getStatus(HBeaconStatusError,"Http response error");
	  }
 	}
 }else
     {
       return getStatus(HBeaconStatusError,"Network Init error!");
     }

       return status;
}


/**
 ****************************************************************************************
 * @brief service init function
 * @param[in] scanner id length.
 * @return  status.
 ****************************************************************************************
 */
HBeaconStatus HBeaconScanServiceInit(HBeaconScanService *service,
				     uint8_t userLen,
				     uint8_t username[userLen],
				     uint8_t passwdLen,
				     uint8_t password[passwdLen])
{

  if (service == NULL) {
    return getStatus(HBeaconStatusError,"Service is NULL");
  }

  _username = (uint8_t *)malloc(userLen+1);
  memcpy(_username, username, userLen+1);

  _password = (uint8_t *)malloc(passwdLen+1);
  memcpy(_password, password, passwdLen+1);


  // global libcurl init
  CURLcode code = curl_global_init(CURL_GLOBAL_ALL);
  if (code) {
    return getStatus(HBeaconStatusErrorCurl,"Service init failed!");
  }

  service->configureScanner = configureScannerInternal;
  service->processPacket = processPacketInternal;

  return getStatus(HBeaconStatusOk,"Server Init");
}


/**
 ****************************************************************************************
 * @brief service shoudowm function
 * @param[in] scanner id length.
 * @return  status.
 ****************************************************************************************
 */
HBeaconStatus HBeaconScanServiceShutdown(HBeaconScanService *service)
{


  if (_username) {
    hbprintf("username: %s\n", _username);
    free(_username);
  }
  if (_password) {
    hbprintf("password: %s\n", _password);
    free(_password);
  }

  
  //TODO: cleanup the black list
  ScannerlistElement *sl_elem, *sl_tmp;
  DL_FOREACH_SAFE(_scannerlist, sl_elem, sl_tmp) {
    DL_DELETE(_scannerlist, sl_elem);
    free(sl_elem->scanner);
    curl_easy_cleanup(sl_elem->curl);
    free(sl_elem);
  }
  

  blacklistCleanup(&_cachelist);
  
  blacklistCleanup(&_blacklist);

  // cleanup the global curl
  curl_global_cleanup();

  service->configureScanner = NULL;
  service->processPacket = NULL;

  return getStatus(HBeaconStatusOk,"Shot down!");;
}
