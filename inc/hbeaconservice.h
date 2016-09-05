/**                                                                                                                                                                                                                
****************************************************************************************                                                                                                                           
*                                                                                                                                                                                                                  
* @file hbeaconscanservice.h                                                                                                                                                                                       
*                                                                                                                                                                                                                  
* @brief hbeacon scan service head file                                                                                                                                                                       
*                                                                                                                                                                                                                  
* Copyright (C) Huami  2016                                                                                                                                                                                        
*                                                                                                                                                                                                                  
* VERSION 1.5                                                                                                                                                                                                                  
****************************************************************************************                                                                                                                           
*/

#ifndef __HBEACONSCANSERVICE_H
#define __HBEACONSCANSERVICE_H

#include <stdint.h>

typedef enum {
  HBeaconStatusOk = 0,
  HBeaconStatusError = 1,
  HBeaconStatusErrorBlacklist = 2,
  HBeaconStatusErrorCurl = 4,
  HBeaconStatusErrorLicense = 8,
  HBeaconStatusDataCached = 9,
} HBeaconStatusCode;

typedef enum {
  HBeaconScannerSetup = 0,
  HBeaconScannerRemove = 1,
} HBeaconScannerAction;

typedef enum {
  HBeaconAdvDataType = 0,
  HBeaconScanRspDataType = 4,
} HBeaconAdvPacketType;

typedef struct _hbeacon_status {
  HBeaconStatusCode code;
  uint8_t message[64];
} HBeaconStatus;

#define ScannerIDMaxLength (64)
#define JSON_CACHE_TIME (3)

typedef HBeaconStatus (*ConfigureScanner_t)(HBeaconScannerAction action,
					uint8_t length,
					uint8_t scannerID[length]);

typedef HBeaconStatus (*ProcessPacket_t)(uint8_t scannerIDlen,
					 uint8_t scannerID[scannerIDlen],
					 HBeaconAdvPacketType type,
					 uint8_t macAddr[6],
					 uint8_t dataLen,
					 uint8_t rawData[dataLen],
					 int rssiValue);

typedef struct _hbeacon_scan_service {
  ConfigureScanner_t configureScanner;
  ProcessPacket_t processPacket;
} HBeaconScanService;

HBeaconStatus HBeaconScanServiceInit(HBeaconScanService *service,
				     uint8_t userLen,
				     uint8_t username[userLen],
				     uint8_t passwdLen,
				     uint8_t password[passwdLen]);

HBeaconStatus HBeaconScanServiceShutdown(HBeaconScanService *service);

//TODO&FIXME: remove before release
void IterateScannerInternal();

#endif
