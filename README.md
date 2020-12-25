# Example for Firmware OTA with AWS IoT on Nuvoton's Mbed Enabled boards

This is an example to show firmware Over-The-Air (OTA) with [AWS IoT service](https://aws.amazon.com/console/) on Nuvoton's Mbed Enabled boards.
It relies on the following modules:

-   [Mbed OS](https://github.com/ARMmbed/mbed-os):
    Is an open source embedded operating system designed specifically for the "things" in the Internet of Things.
-   [AWS IoT SDK port for Mbed OS](https://github.com/OpenNuvoton/mbed-client-for-aws/):
    Provides the port of the AWS IoT SDK for Mbed OS. It can be used to connect devices running Mbed OS to the AWS IoT Core service over MQTT.

## Support targets

Platform                                                                    |  Connectivity     | Storage for firmware OTA                  
----------------------------------------------------------------------------|-------------------|-------------------------------------------
[NuMaker-PFM-M487](https://developer.mbed.org/platforms/NUMAKER-PFM-M487/)  | Ethernet          | SPI flash                                 
[NuMaker-IoT-M487](https://os.mbed.com/platforms/NUMAKER-IOT-M487/)         | Wi-Fi ESP8266     | SPI flash                                 

## Support development tools

-   [Arm's Mbed Online Compiler](https://os.mbed.com/docs/mbed-os/v6.6/tools/developing-mbed-online-compiler.html)
-   [Arm's Mbed Studio](https://os.mbed.com/docs/mbed-os/v6.6/tools/developing-mbed-studio.html)
-   [Arm's Mbed CLI](https://os.mbed.com/docs/mbed-os/v6.6/tools/developing-mbed-cli.html)

## Developer guide

This section is intended for developers to get started, import the example application, compile with Mbed CLI, and get it running and firmware OTA with AWS IoT service.

### Hardware requirements

-   Nuvoton's Mbed Enabled board, [NuMaker-IoT-M487](https://os.mbed.com/platforms/NUMAKER-IOT-M487/) for example

### Software requirements

-   [Arm's Mbed CLI](https://os.mbed.com/docs/mbed-os/v6.6/tools/developing-mbed-cli.html)
-   [NuMicro ICP Programming Tool](https://www.nuvoton.com/tool-and-software/software-development-tool/programmer/)

### Hardware setup

-   Switch target board to **ICE** mode
-   Connect target board to host through USB

### Compile with Mbed CLI

In the following, we take [NuMaker-IoT-M487](https://os.mbed.com/platforms/NUMAKER-IOT-M487/) as example board to show this example.

1.  Clone the example and navigate into it
    ```sh
    $ git clone https://github.com/OpenNuvoton/NuMaker-mbed-AWSn-IoT-CSDK-OTA-example
    $ cd NuMaker-mbed-AWS-IoT-CSDK-OTA-example
    ```
1.  Deploy necessary libraries
    ```sh
    $ mbed deploy
    ```
1.  Configure network interface
    In `mbed_app.json`, configure WiFi **SSID**/**PASSWORD**.
    ```json
        "nsapi.default-wifi-ssid"                   : "\"SSID\"",
        "nsapi.default-wifi-password"               : "\"PASSWORD\"",
    ```

1.  In `configs/aws_config.h`, provide AWS connection parameters: **AWS_IOT_ENDPOINT**, **CLIENT_IDENTIFIER**, and **THING_NAME**.

1.  In `configs/aws_credentials.c`, provide relevant AWS credentials.

1.  Build the example on **NUMAKER_IOT_M487** target and **ARM** toolchain
    ```sh
    $ mbed compile -m NUMAKER_IOT_M487 -t ARM
    ```

    Add version suffix `_V1.0.0` to the built image file name for distinct from below. This file is for flash later.

    BUILD/NUMAKER_IOT_M487/`ARM/NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin`
    → `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin`

1.  Re-build the example with increasing version of the application.
    For example, set `APP_VERSION_MAJOR/MINOR/BUILD` in `configs/aws_config.h` to `1/0/1`.
    ```sh
    $ mbed compile -m NUMAKER_IOT_M487 -t ARM
    ```

    Add version suffix `_V1.0.1` to the built image file name for distinct from above. This file is for upload to AWS S3 bucket later.

    BUILD/NUMAKER_IOT_M487/ARM/`NuMaker-mbed-AWS-IoT-CSDK-OTA-example.bin`
    → `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin`

### Flash the images

1.  Open **NuMicro ICP Programming Tool** → Select **M480 Series** → Connect

1.  Flash LDROM bootloader image into LDROM:

    In **Load File** group, click **LDROM** and select `bootloader/Bootloader_LDROM.bin` file
    → In **Programming** group, check only **LDROM** option → Start
1.  Flash application image into APROM `0x0`:

    In **Load File** group, click **APROM**, select `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.0.bin` file, and set **Offset** to `0x0`
    → In **Programming** group, check only **APROM** option → Start

1.  Flash Cloner bootloader image into ARPOM `0x72000`:

    In **Load File** group, click **APROM**, select `bootloader/Bootloader_Cloner.bin` file, and set **Offset** to `0x72000`
    → In **Programming** group, check only **APROM** option → Start

**NOTE**: The operatioins above require NuMaker-IoT-M487 board swiched to **ICE** mode.

**NOTE**: The order of flashing application image and Cloner bootloader image is significant. This tool will erase all the blocks starting from the one the start address is located to the end.

### Operations on AWS IoT Console

#### Prerequisites for the AWS Over-The-Air Update (OTA)

Prepare the prerequisites following [the guide](https://github.com/aws/aws-iot-device-sdk-embedded-C#prerequisites-for-the-aws-over-the-air-update-ota-demos).

#### Scheduling an OTA Update Job

Schedule an OTA Update job following [the guide](https://github.com/aws/aws-iot-device-sdk-embedded-C#scheduling-an-ota-update-job).

The following steaps are re-statements of above and adapted to this port:

1.  Go to the A[WS IoT Core console](http://console.aws.amazon.com/iot/).

1.  Manage → Jobs → Create → Create a FreeRTOS OTA update job → Select the corresponding name for your device from the thing list.

    **NOTE**: This port supports MQTT protocol only.

1.  Sign a new firmware → Create a new profile → Select any SHA-ECDSA signing platform → Upload the code signing certificate [from prerequisites](#prerequisites-for-the-aws-over-the-air-update-ota) and provide its path on the device.

    **NOTE**: For **Pathname of code signing certificate on device**, set to PKCS #11 label `pkcs11configLABEL_CODE_VERIFICATION_KEY` defined at the file below.
    Its value could be `Code_Verify_Key` for example.

    ```
    mbed-client-for-aws/mbed/COMPONENT_AWSIOT_PKCS11/core_pkcs11_config.h
    ```

1.  Select the image → Select the bucket you created during the [prerequisite steps](#prerequisites-for-the-aws-over-the-air-update-ota) → Upload the binary `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin`.

1.  For **Pathname of file on device**, it is not used. Just set to `NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin` for example.

1.  Select the IAM role created during the [prerequisite steps](#prerequisites-for-the-aws-over-the-air-update-ota).

1.  Create the Job.


### Monitor the application through host console

Configure host terminal program with **115200/8-N-1**, and you should see log similar to below:

Device not provisioned yet. Simulate the provision process:
```
The device has not provisioned yet. Try to provision it...
Provision for development...
Reset kvstore...
Reset kvstore...OK
Provision for development...OK
```

Application version before update should be `1.0.0`.
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1649] *** Application version: 1.0.0
```

Connect to AWS MQTT server:
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1650] Connecting to the network...
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1661] MAC: a4:cf:12:b7:82:3b
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1662] Connection Success
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1469] OTA over MQTT demo, Application version 1.0.0
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:941] Establishing a TLS session to a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com:8883.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1080] Creating an MQTT connection to a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:886] Packet received. ReceivedBytes=2.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt_serializer.c:970] CONNACK session present bit not set.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt_serializer.c:912] Connection accepted.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1563] Received MQTT CONNACK successfully from broker.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1829] MQTT connection established with the broker.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1049] MQTT connection successfully established with broker.
```

Go firmware OTA flow:
```
otaPal_GetPlatformImageState] image state [0] -- Flag[0xff].
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2798] Current State=[RequestingJob], Event=[Start], New state=[RequestingJob]
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1551]  Received: 0   Queued: 0   Processed: 0   Dropped: 0
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1279] SUBSCRIBE topic $aws/things/Nuvoton-Mbed-D001/jobs/$next/get/accepted to broker.


[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota_mqtt.c:387] Subscribed to MQTT topic: $aws/things/Nuvoton-Mbed-D001/jobs/$next/get/accepted
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:886] Packet received. ReceivedBytes=3.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:775] Received SUBACK.


[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1551]  Received: 0   Queued: 0   Processed: 0   Dropped: 0
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1279] SUBSCRIBE topic $aws/things/Nuvoton-Mbed-D001/jobs/notify-next to broker.


[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota-for-aws-iot-embedded-sdk\source\ota_mqtt.c:417] Subscribed to MQTT topic: $aws/things/Nuvoton-Mbed-D001/jobs/notify-next
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:886] Packet received. ReceivedBytes=3.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:775] Received SUBACK.


[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1551]  Received: 0   Queued: 0   Processed: 0   Dropped: 0
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1339] Sent PUBLISH packet to broker $aws/things/Nuvoton-Mbed-D001/jobs/$next/get to broker.


[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2798] Current State=[WaitingForJob], Event=[RequestJobDocument], New state=[WaitingForJob]
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:886] Packet received. ReceivedBytes=2.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1162] Ack packet deserialized with result: MQTTSuccess.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1175] State record updated. New state=MQTTPublishDone.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:792] PUBACK received for packet id 3.


[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:886] Packet received. ReceivedBytes=114.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1045] De-serialized incoming PUBLISH packet: DeserializerResult=MQTTSuccess.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1058] State record updated. New state=MQTTPublishDone.
[INFO] [DEMO] [.\demo_ota_mqtt\mqtt_subscription_manager.c:91] Invoking subscription callback of matching topic filter: TopicFilter=$aws/things/Nuvoton-Mbed-D001/jobs/$next/get/accepted, TopicName=$aws/things/Nuvoton-Mbed-D001/jobs/$next/get/accepted
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:697] Received job message callback, size 59.
```

Receive a new OTA update job:
```
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:886] Packet received. ReceivedBytes=593.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1045] De-serialized incoming PUBLISH packet: DeserializerResult=MQTTSuccess.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1058] State record updated. New state=MQTTPublishDone.
[INFO] [DEMO] [.\demo_ota_mqtt\mqtt_subscription_manager.c:91] Invoking subscription callback of matching topic filter: TopicFilter=$aws/things/Nuvoton-Mbed-D001/jobs/notify-next, TopicName=$aws/things/Nuvoton-Mbed-D001/jobs/notify-next
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:697] Received job message callback, size 545.


[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:1595] Extracted parameter: [key: value]=[execution.jobId: AFR_OTA-ccli8-ota-update-job-013]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:1595] Extracted parameter: [key: value]=[execution.jobDocument.afr_ota.streamname: AFR_OTA-bf57451d-9efc-4e55-934c-187e008aa49d]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:1595] Extracted parameter: [key: value]=[execution.jobDocument.afr_ota.protocols: ["MQTT"]]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:1595] Extracted parameter: [key: value]=[filepath: NuMaker-mbed-AWS-IoT-CSDK-OTA-example_V1.0.1.bin]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:1634] Extracted parameter: [key: value]=[filesize: 356672]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:1634] Extracted parameter: [key: value]=[fileid: 0]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:1595] Extracted parameter: [key: value]=[certfile: Code_Verify_Key]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:1525] Extracted parameter [ sig-sha256-ecdsa: MEQCIGS6bA+XZzLfIF4YJ0qPn5xqDe95... ]
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2134] Job document was accepted. Attempting to begin the update.
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2167] Job parsing sccess: OtaJobParseErr_t=OtaJobParseErrNone, Job name=AFR_OTA-ccli8-ota-update-job-013
```

Downloading:
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2409] Received valid file block: Block index=148, Size=2048
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2629] Number of blocks remaining: 29
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2798] Current State=[WaitingForFileBlock], Event=[ReceivedFileBlock], New state=[WaitingForFileBlock]
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:886] Packet received. ReceivedBytes=2167.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1045] De-serialized incoming PUBLISH packet: DeserializerResult=MQTTSuccess.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1058] State record updated. New state=MQTTPublishDone.
[INFO] [DEMO] [.\demo_ota_mqtt\mqtt_subscription_manager.c:91] Invoking subscription callback of matching topic filter: TopicFilter=$aws/things/Nuvoton-Mbed-D001/streams/AFR_OTA-bf57451d-9efc-4e55-934c-187e008aa49d/data/cbor, TopicName=$aws/things/Nuvoton-Mbed-D001/streams/AFR_OTA-bf57451d-9efc-4e55-934c-187e008aa49d/data/cbor
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:730] Received data message callback, size 2073.
```

Downloading completed:
```
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2579] Received final block of the update.
```

Verify code signature and prepare for firmware update:
```
[prvPAL_CheckFileSignature] Started sig-sha256-ecdsa signature verification, file: Code_Verify_Key
[prvPAL_ReadAndAssumeCertificate] Using cert with label: Code_Verify_Key OK
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1551]  Received: 175   Queued: 175   Processed: 174   Dropped: 0
[otaPal_CloseFile] sig-sha256-ecdsa signature verification passed.
[prvContextUpdateImageHeaderAndTrailer] OTA Sequence Number: 21
[prvContextUpdateImageHeaderAndTrailer] Image - Start: 0x00000000, End: 0x0005713f
[prvContextUpdateImageHeaderAndTrailer] Writing Trailer at: 0x00071000
[otaPal_CloseFile] Image header updated.
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:2600] Received entire update and validated the signature.
```

Reboot:
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:619] Received OtaJobEventActivate callback from OTA Agent.
[otaPal_ActivateNewImage] Activating the new MCU image.
[otaPal_ResetDevice] Resetting the device.
```

Reboot to bootloader for firmware update:
```
Boot from LDROM successful
read Magic code: @AFRTOS
Jump to APROM Cloner
Will boot from 0x00072000
SPIM get JEDEC ID=0xEF, 0x40, 0x16
Boot to AWS Cloner
read Magic code     : @AFRTOS
read Image flag     : 0xFF
read Sequence Num   : 0x00000015
read Start addr     : 0x00000000
read End addr       : 0x0005713F
read Exec addr      : 0x00000000
read Hardware ID    : 0x2000AAB4
read Reserved data  : 0x200011D8
Check OTA image success
Clone OTA image from SPI Flash to APROM
page_num: 0x58
Erasing APROM ...
Erasing page_num = 0x0
Erasing page_num = 0x1000
......
Erasing page_num = 0x56000
Erasing page_num = 0x57000
Clone APROM ...
Clone done.
Checksum OK. CRC32: 0x0
Update OTA header ...
```

Reboot to application (updated)
```
The device has provisioned. Skip provision process
```

Application version after update should be `1.0.1`.
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1649] *** Application version: 1.0.1
```

Re-connect to AWS MQTT servier:
```
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1650] Connecting to the network...
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1661] MAC: a4:cf:12:b7:82:3b
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1662] Connection Success
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1469] OTA over MQTT demo, Application version 1.0.1
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:941] Establishing a TLS session to a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com:8883.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1080] Creating an MQTT connection to a1fljoeglhtf61-ats.iot.us-east-2.amazonaws.com.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:886] Packet received. ReceivedBytes=2.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt_serializer.c:970] CONNACK session present bit not set.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt_serializer.c:912] Connection accepted.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1563] Received MQTT CONNACK successfully from broker.
[INFO] [MQTT] [.\mbed-client-for-aws\COMPONENT_AWSIOT_MQTT\coreMQTT\source\core_mqtt.c:1829] MQTT connection established with the broker.
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:1049] MQTT connection successfully established with broker.
```

Complete rest of firmware OTA:
```
......
[INFO] [OTA] [.\mbed-client-for-aws\COMPONENT_AWSIOT_OTA\ota.c:766] Beginning self-test.
[otaPal_GetPlatformImageState] image state [1] -- Flag[0xfe].
[INFO] [DEMO] [.\demo_ota_mqtt\ota_demo_core_mqtt.cpp:646] Received OtaJobEventStartTest callback from OTA Agent.
[otaPal_SetPlatformImageState] Accepted and committed final image.
[otaPal_SetPlatformImageState] image state [2] ---Flag[0xfc].
......
```

### Walk through source code

#### AWS configuration (`configs/`)

AWS connection parameters and credentails are placed here.

#### Pre-main (`pre-main/`)

In Mbed OS boot sequence, `mbed_main()`, designed for user application override, is run before `main()`.
Here, it is used to run the following tasks:

1.  Simulate provision process for development (`provision/`)
    1.  Reset [KVStore](https://os.mbed.com/docs/mbed-os/v6.6/apis/kvstore.html)
    1.  Inject AWS credentials
    1.  Mark the device as provisioned
    ```
    The device has not provisioned yet. Try to provision it...
    Provision for development...
    Reset kvstore...
    Reset kvstore...OK
    Provision for development...OK
    ```

    **NOTE**: This function is for development requirement. Remove `provision/` directory for production.

1.  Set up event queue for dispatching host command (`host-stdin/`)

    Currently, press the following command:
    1.  `h` for printing heap statistics
        ```
        ** MBED HEAP STATS **
        **** current_size: 61830
        **** max_size    : 71866
        *****************************
        ```

    1.  `s` for printing stack statistics
        ```
        ** MBED THREAD STACK STATS **
        Thread: 0x20005718, Stack size: 2048, Max stack: 584
        Thread: 0x20008eac, Stack size: 4096, Max stack: 1144
        Thread: 0x20008864, Stack size: 512, Max stack: 64
        Thread: 0x200088ec, Stack size: 8192, Max stack: 3104
        Thread: 0x200088a8, Stack size: 768, Max stack: 96
        *****************************
        ```

    1.  `r` for resetting system
        ```
        System reset after 2 secs...
        ```

    **NOTE**: This function is for development requirement. Remove `host-stdin/` directory for production.

#### Main with firmware OTA over MQTT (`demo_ota_mqtt/ota_demo_core_mqtt.cpp`)

The examplle here is port of [SDK ota_demo_core_mqtt](https://github.com/aws/aws-iot-device-sdk-embedded-C/tree/main/demos/ota/ota_demo_core_mqtt) and shows firmware OTA with AWS IoT over MQTT.

**NOTE**: Disable write-protect and hold functions of on-board SPI flash.
          For re-designed board which has had /WP and ?HOLD pins pull-high,
          remove the code fragment below to spare these two GPIO pins.

```C++
#if defined(TARGET_NUMAKER_PFM_M487) || defined(TARGET_NUMAKER_IOT_M487)
DigitalOut onboard_spi_wp(PC_5, 1);
DigitalOut onboard_spi_hold(PC_4, 1);
#endif
```
