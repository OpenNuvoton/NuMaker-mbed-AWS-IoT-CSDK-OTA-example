/*
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file ota_demo_core_mqtt.c
 * @brief OTA update example using coreMQTT.
 */

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

/* Mbed includes. */
#include "mbed.h"
#include "mbed_trace.h"
#include "mbed_stats.h"
/* Include Demo Config as the first non-system header. */
#include "demo_config.h"

/* Include credential file */
#include "aws_credentials_provision.h"

/* Mbed TLSSocket sockets transport implementation. */
#include "transport_mbed_tls.h"
#define MBED_HEAP_STATS_ENABLED 1

#if MBED_HEAP_STATS_ENABLED
    mbed_stats_heap_t heap_stats;
#endif

/* Clock for timer. */
extern "C" {
#include "aws-iot-device-sdk-embedded-C/platform/include/clock.h"
}

/* MQTT include. */
extern "C" {
#include "core_mqtt.h"
#include "mqtt_subscription_manager.h"
}

/*Include backoff algorithm header for retry logic.*/
extern "C" {
#include "backoff_algorithm.h"
}

/* OTA Library include. */
/* OtaTimerInterface_t (ota_os_interface.h) has member 'delete' which is C++ reserved
 * keyword. Try get around it. */
#define delete  delete_
extern "C" {
#include "ota.h"
#include "ota_config.h"
}
#undef delete

/* OTA Library Interface include. */
#include "ota_os_mbed.h"
extern "C" {
#include "ota_mqtt_interface.h"
}
#include "ota_pal_mbed.h"

/* Include firmware version struct definition. */
extern "C" {
#include "ota_appversion32.h"
}

/**
 * These configuration settings are required to run the OTA demo which uses mutual authentication.
 * Throw compilation error if the below configs are not defined.
 */
#ifndef AWS_IOT_ENDPOINT
    #error "Please define AWS IoT MQTT broker endpoint(AWS_IOT_ENDPOINT) in demo_config.h."
#endif

#ifndef CLIENT_IDENTIFIER
    #error "Please define a unique client identifier, CLIENT_IDENTIFIER, in demo_config.h."
#endif

#ifndef THING_NAME
    #error "Please define a thing name, THING_NAME, in demo_config.h."
#endif

/**
 * @brief ALPN (Application-Layer Protocol Negotiation) protocol name for AWS IoT MQTT.
 *
 * This will be used if the AWS_MQTT_PORT is configured as 443 for AWS IoT MQTT broker.
 * Please see more details about the ALPN protocol for AWS IoT MQTT endpoint
 * in the link below.
 * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
 */
/* The original format is for openssl API SSL_set_alpn_protos(...). Remove the length prefix
 * to fit mbedtls API mbedtls_ssl_conf_alpn_protocols. */
//#define AWS_IOT_MQTT_ALPN                   "\x0ex-amzn-mqtt-ca"
#define AWS_IOT_MQTT_ALPN                   "x-amzn-mqtt-ca"

/**
 * @brief Length of ALPN protocol name.
 */
#define AWS_IOT_MQTT_ALPN_LENGTH            ( ( uint16_t ) ( sizeof( AWS_IOT_MQTT_ALPN ) - 1 ) )

/**
 * @brief This is the ALPN (Application-Layer Protocol Negotiation) string
 * required by AWS IoT for password-based authentication using TCP port 443.
 */
/* Same reason as above for removing the length prefix */
//#define AWS_IOT_PASSWORD_ALPN           "\x04mqtt"
#define AWS_IOT_PASSWORD_ALPN           "mqtt"

/**
 * @brief Length of password ALPN.
 */
#define AWS_IOT_PASSWORD_ALPN_LENGTH    ( ( uint16_t ) ( sizeof( AWS_IOT_PASSWORD_ALPN ) - 1 ) )

/**
 * @brief Length of MQTT server host name.
 */
#define AWS_IOT_ENDPOINT_LENGTH             ( ( uint16_t ) ( sizeof( AWS_IOT_ENDPOINT ) - 1 ) )

/**
 * @brief Length of client identifier.
 */
#define CLIENT_IDENTIFIER_LENGTH            ( ( uint16_t ) ( sizeof( CLIENT_IDENTIFIER ) - 1 ) )

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define TRANSPORT_SEND_RECV_TIMEOUT_MS      ( 200U )

/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS             ( 5000U )

/**
 * @brief The maximum time interval in seconds which is allowed to elapse
 * between two Control Packets.
 *
 * It is the responsibility of the Client to ensure that the interval between
 * Control Packets being sent does not exceed the this Keep Alive value. In the
 * absence of sending any other Control Packets, the Client MUST send a
 * PINGREQ Packet.
 */
#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS    ( 60U )

/**
 * @brief Timeout for MQTT_ProcessLoop function in milliseconds.
 */
#define MQTT_PROCESS_LOOP_TIMEOUT_MS        ( 1000U )

/**
 * @brief Period for demo loop sleep in milliseconds.
 */
#define OTA_EXAMPLE_LOOP_SLEEP_PERIOD_MS    ( 5U )

/**
 * @brief Size of the network buffer to receive the MQTT message.
 *
 * The largest message size is data size from the AWS IoT streaming service,
 * otaconfigFILE_BLOCK_SIZE + extra for headers.
 */

#define OTA_NETWORK_BUFFER_SIZE                  ( otaconfigFILE_BLOCK_SIZE + 128 )

/**
 * @brief The delay used in the main OTA Demo task loop to periodically output the OTA
 * statistics like number of packets received, dropped, processed and queued per connection.
 */
#define OTA_EXAMPLE_TASK_DELAY_MS                ( 1000U )

/**
 * @brief The timeout for waiting for the agent to get suspended after closing the
 * connection.
 */
#define OTA_SUSPEND_TIMEOUT_MS                   ( 5000U )

/**
 * @brief The timeout for waiting before exiting the OTA demo.
 */
#define OTA_DEMO_EXIT_TIMEOUT_MS                 ( 3000U )

/**
 * @brief The maximum size of the file paths used in the demo.
 */
#define OTA_MAX_FILE_PATH_SIZE                   ( 260U )

/**
 * @brief The maximum size of the stream name required for downloading update file
 * from streaming service.
 */
#define OTA_MAX_STREAM_NAME_SIZE                 ( 128U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS    ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS         ( 500U )

/**
 * @brief Number of milliseconds in a second.
 */
#define NUM_MILLISECONDS_IN_SECOND               ( 1000U )

/**
 * @brief The maximum number of retries for connecting to server.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS            ( 5U )

/**
 * @brief The MQTT metrics string expected by AWS IoT.
 */
#define METRICS_STRING                           "?SDK=" OS_NAME "&Version=" OS_VERSION "&Platform=" HARDWARE_PLATFORM_NAME "&OTALib=" OTA_LIB

/**
 * @brief The length of the MQTT metrics string expected by AWS IoT.
 */
#define METRICS_STRING_LENGTH                    ( ( uint16_t ) ( sizeof( METRICS_STRING ) - 1 ) )


#ifdef CLIENT_USERNAME

/**
 * @brief Append the username with the metrics string if #CLIENT_USERNAME is defined.
 *
 * This is to support both metrics reporting and username/password based client
 * authentication by AWS IoT.
 */
    #define CLIENT_USERNAME_WITH_METRICS    CLIENT_USERNAME METRICS_STRING
#endif

/**
 * @brief The common prefix for all OTA topics.
 */
#define OTA_TOPIC_PREFIX           "$aws/things/"

/**
 * @brief The string used for jobs topics.
 */
#define OTA_TOPIC_JOBS             "jobs"

/**
 * @brief The string used for streaming service topics.
 */
#define OTA_TOPIC_STREAM           "streams"

/**
 * @brief The length of #OTA_TOPIC_PREFIX
 */
#define OTA_TOPIC_PREFIX_LENGTH    ( ( uint16_t ) ( sizeof( OTA_TOPIC_PREFIX ) - 1U ) )

/*-----------------------------------------------------------*/

/**
 * @brief Struct for firmware version.
 */
const AppVersion32_t appFirmwareVersion =
{
    .u = {
        #if ( defined( __BYTE_ORDER__ ) && defined( __ORDER_LITTLE_ENDIAN__ ) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ) || ( __little_endian__ == 1 ) || WIN32 || ( __BYTE_ORDER == __LITTLE_ENDIAN )
        .x = {
            APP_VERSION_BUILD,
            APP_VERSION_MINOR,
            APP_VERSION_MAJOR,
        },
        #elif ( defined( __BYTE_ORDER__ ) && defined( __ORDER_BIG_ENDIAN__ ) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ ) || ( __big_endian__ == 1 ) || ( __BYTE_ORDER == __BIG_ENDIAN )
        .x = {
            APP_VERSION_MAJOR,
            APP_VERSION_MINOR,
            APP_VERSION_BUILD,
        },
        #else /* if ( defined( __BYTE_ORDER__ ) && defined( __ORDER_LITTLE_ENDIAN__ ) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ) || ( __little_endian__ == 1 ) || WIN32 || ( __BYTE_ORDER == __LITTLE_ENDIAN ) */
        #error "Unable to determine byte order!"
        #endif /* if ( defined( __BYTE_ORDER__ ) && defined( __ORDER_LITTLE_ENDIAN__ ) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ) || ( __little_endian__ == 1 ) || WIN32 || ( __BYTE_ORDER == __LITTLE_ENDIAN ) */
    }
};

/**
 * @brief Network connection context used in this demo.
 */
static TlsNetworkContext_t networkContext;

/**
 * @brief MQTT connection context used in this demo.
 */
static MQTTContext_t mqttContext;

/**
 * @brief Keep a flag for indicating if the MQTT connection is alive.
 */
static bool mqttSessionEstablished = false;

/**
 * @brief Mutex for synchronizing coreMQTT API calls.
 */
static rtos::Mutex mqttMutex;

/**
 * @brief Semaphore for synchronizing buffer operations.
 */
static rtos::Semaphore bufferSemaphore(1);

/** 
 * @brief OTA Agent thread
 */
rtos::Thread otaAgentThread(osPriorityNormal, 4096);

/**
 * @brief Enum for type of OTA messages received.
 */
typedef enum OtaMessageType
{
    OtaMessageTypeJob = 0,
    OtaMessageTypeStream,
    OtaNumOfMessageType
} OtaMessageType_t;

/**
 * @brief The network buffer must remain valid when OTA library task is running.
 */
static uint8_t otaNetworkBuffer[ OTA_NETWORK_BUFFER_SIZE ];

/**
 * @brief Update File path buffer.
 */
uint8_t updateFilePath[ OTA_MAX_FILE_PATH_SIZE ];

/**
 * @brief Certificate File path buffer.
 */
uint8_t certFilePath[ OTA_MAX_FILE_PATH_SIZE ];

/**
 * @brief Stream name buffer.
 */
uint8_t streamName[ OTA_MAX_STREAM_NAME_SIZE ];

/**
 * @brief Decode memory.
 */
uint8_t decodeMem[ otaconfigFILE_BLOCK_SIZE ];

/**
 * @brief Bitmap memory.
 */
uint8_t bitmap[ OTA_MAX_BLOCK_BITMAP_SIZE ];

/**
 * @brief Event buffer.
 */
static OtaEventData_t eventBuffer[ otaconfigMAX_NUM_OTA_DATA_BUFFERS ];

/**
 * @brief The buffer passed to the OTA Agent from application while initializing.
 */
static OtaAppBuffer_t otaBuffer =
{
    .pUpdateFilePath    = updateFilePath,
    .updateFilePathsize = OTA_MAX_FILE_PATH_SIZE,
    .pCertFilePath      = certFilePath,
    .certFilePathSize   = OTA_MAX_FILE_PATH_SIZE,
    .pStreamName        = streamName,
    .streamNameSize     = OTA_MAX_STREAM_NAME_SIZE,
    .pDecodeMemory      = decodeMem,
    .decodeMemorySize   = otaconfigFILE_BLOCK_SIZE,
    .pFileBitmap        = bitmap,
    .fileBitmapSize     = OTA_MAX_BLOCK_BITMAP_SIZE
};

/*-----------------------------------------------------------*/

/**
 * @brief Sends an MQTT CONNECT packet over the already connected TCP socket.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] createCleanSession Creates a new MQTT session if true.
 * If false, tries to establish the existing session if there was session
 * already present in broker.
 * @param[out] pSessionPresent Session was already present in the broker or not.
 * Session present response is obtained from the CONNACK from broker.
 *
 * @return EXIT_SUCCESS if an MQTT session is established;
 * EXIT_FAILURE otherwise.
 */
static int establishMqttSession( MQTTContext_t * pMqttContext );


/**
 * @brief Publish message to a topic.
 *
 * This function publishes a message to a given topic & QoS.
 *
 * @param[in] pacTopic Mqtt topic filter.
 *
 * @param[in] topicLen Length of the topic filter.
 *
 * @param[in] pMsg Message to publish.
 *
 * @param[in] msgSize Message size.
 *
 * @param[in] qos Quality of Service
 *
 * @return OtaMqttSuccess if success , other error code on failure.
 */
static OtaMqttStatus_t mqttPublish( const char * const pacTopic,
                                    uint16_t topicLen,
                                    const char * pMsg,
                                    uint32_t msgSize,
                                    uint8_t qos );

/**
 * @brief Subscribe to the MQTT topic filter, and registers the handler for the topic filter with the subscription manager.
 *
 * This function subscribes to the Mqtt topics with the Quality of service
 * received as parameter. This function also registers a callback for the
 * topicfilter.
 *
 * @param[in] pTopicFilter Mqtt topic filter.
 *
 * @param[in] topicFilterLength Length of the topic filter.
 *
 * @param[in] qos Quality of Service
 *
 * @return OtaMqttSuccess if success , other error code on failure.
 */
static OtaMqttStatus_t mqttSubscribe( const char * pTopicFilter,
                                      uint16_t topicFilterLength,
                                      uint8_t qos );

/**
 * @brief Unsubscribe to the Mqtt topics.
 *
 * This function unsubscribes to the Mqtt topics with the Quality of service
 * received as parameter.
 *
 * @param[in] pTopicFilter Mqtt topic filter.
 *
 * @param[in] topicFilterLength Length of the topic filter.
 *
 * @param[qos] qos Quality of Service
 *
 * @return  OtaMqttSuccess if success , other error code on failure.
 */
static OtaMqttStatus_t mqttUnsubscribe( const char * pTopicFilter,
                                        uint16_t topicFilterLength,
                                        uint8_t qos );

/**
 * @brief Thread to call the OTA agent task.
 *
 * @param[in] pParam Can be used to pass down functionality to the agent task
 */
static void otaThread( void * pParam );

/**
 * @brief Start OTA demo.
 *
 * The OTA task is created with initializing the OTA agent and
 * setting the required interfaces. The demo loop then starts,
 * establishing an MQTT connection with the broker and waiting
 * for an update. After a successful update the OTA agent requests
 * a manual reset to the downloaded executable.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE.
 */
static int startOTADemo( void );

/**
 * @brief Set OTA interfaces.
 *
 * @param[in]  pOtaInterfaces pointer to OTA interface structure.
 */
static void setOtaInterfaces( OtaInterfaces_t * pOtaInterfaces );

/**
 * @brief Disconnect from the MQTT broker and close connection.
 *
 */
static void disconnect( void );

/**
 * @brief Attempt to connect to the MQTT broker.
 *
 * @return int EXIT_SUCCESS if a connection is established.
 */
static int establishConnection( void );

/**
 * @brief Initialize MQTT by setting up transport interface and network.
 *
 * @param[in] pMqttContext Structure representing MQTT connection.
 * @param[in] pNetworkContext Network context to connect on.
 * @return int EXIT_SUCCESS if MQTT component is initialized
 */
static int initializeMqtt( MQTTContext_t * pMqttContext,
                           NetworkContext_t * pNetworkContext );

/**
 * @brief Retry logic to establish a connection to the server.
 *
 * If the connection fails, keep retrying with exponentially increasing
 * timeout value, until max retries, max timeout or successful connect.
 *
 * @param[in] pNetworkContext Network context to connect on.
 * @return int EXIT_FAILURE if connection failed after retries.
 */
static int connectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext );

/**
 * @brief Random number to be used as a back-off value for retrying connection.
 *
 * @return uint32_t The generated random number.
 */
static uint32_t generateRandomNumber();

/* Callbacks used to handle different events. */

/**
 * @brief The OTA agent has completed the update job or it is in
 * self test mode. If it was accepted, we want to activate the new image.
 * This typically means we should reset the device to run the new firmware.
 * If now is not a good time to reset the device, it may be activated later
 * by your user code. If the update was rejected, just return without doing
 * anything and we'll wait for another job. If it reported that we should
 * start test mode, normally we would perform some kind of system checks to
 * make sure our new firmware does the basic things we think it should do
 * but we'll just go ahead and set the image as accepted for demo purposes.
 * The accept function varies depending on your platform. Refer to the OTA
 * PAL implementation for your platform in aws_ota_pal.c to see what it
 * does for you.
 *
 * @param[in] event Event from OTA lib of type OtaJobEvent_t.
 * @return None.
 */
static void otaAppCallback( OtaJobEvent_t event,
                            const void * pData );

/**
 * @brief callback to use with the MQTT context to notify incoming packet events.
 *
 * @param[in] pMqttContext MQTT context which stores the connection.
 * @param[in] pPacketInfo Parameters of the incoming packet.
 * @param[in] pDeserializedInfo Deserialized packet information to be dispatched by
 * the subscription manager to event callbacks.
 */
static void mqttEventCallback( MQTTContext_t * pMqttContext,
                               MQTTPacketInfo_t * pPacketInfo,
                               MQTTDeserializedInfo_t * pDeserializedInfo );

/**
 * @brief Callback registered with the OTA library that notifies the OTA agent
 * of an incoming PUBLISH containing a job document.
 *
 * @param[in] pContext MQTT context which stores the connection.
 * @param[in] pPublishInfo MQTT packet information which stores details of the
 * job document.
 */
static void mqttJobCallback( MQTTContext_t * pContext,
                             MQTTPublishInfo_t * pPublishInfo );

/**
 * @brief Callback that notifies the OTA library when a data block is received.
 *
 * @param[in] pContext MQTT context which stores the connection.
 * @param[in] pPublishInfo MQTT packet that stores the information of the file block.
 */
static void mqttDataCallback( MQTTContext_t * pContext,
                              MQTTPublishInfo_t * pPublishInfo );

static SubscriptionManagerCallback_t otaMessageCallback[ OtaNumOfMessageType ] = { mqttJobCallback, mqttDataCallback };


/* Extra configuration for on-board SPI flash for OTA update
 *
 * We needn't write-protect and hold functions. Configure /WP and /HOLD pins to high.
 *
 * For re-designed board which has had /WP and ?HOLD pins pull-high, remove this code
 * fragment to spare these GPIO pins.
 */
#if defined(TARGET_NUMAKER_PFM_M487) || defined(TARGET_NUMAKER_IOT_M487)
DigitalOut onboard_spi_wp(PC_5, 1);
DigitalOut onboard_spi_hold(PC_4, 1);
#endif

/*-----------------------------------------------------------*/

void otaEventBufferFree( OtaEventData_t * const pxBuffer )
{
    bufferSemaphore.acquire();
    pxBuffer->bufferUsed = false;
    bufferSemaphore.release();
}

/*-----------------------------------------------------------*/

OtaEventData_t * otaEventBufferGet( void )
{
    uint32_t ulIndex = 0;
    OtaEventData_t * pFreeBuffer = NULL;

    bufferSemaphore.acquire();
    {
        for( ulIndex = 0; ulIndex < otaconfigMAX_NUM_OTA_DATA_BUFFERS; ulIndex++ )
        {
            if( eventBuffer[ ulIndex ].bufferUsed == false )
            {
                eventBuffer[ ulIndex ].bufferUsed = true;
                pFreeBuffer = &eventBuffer[ ulIndex ];
                break;
            }
        }
    }
    bufferSemaphore.release();

    return pFreeBuffer;
}

/*-----------------------------------------------------------*/

static void otaAppCallback( OtaJobEvent_t event,
                            const void * pData )
{
    OtaErr_t err = OtaErrUninitialized;

    switch( event )
    {
        case OtaJobEventActivate:
            LogInfo( ( "Received OtaJobEventActivate callback from OTA Agent." ) );
            /* Print memory statics */
            #if MBED_HEAP_STATS_ENABLED
                mbed_stats_heap_get(&heap_stats);
                LogInfo(("Current heap: %lu\r\n", heap_stats.current_size));
                LogInfo(("Max heap size: %lu\r\n", heap_stats.max_size));
                LogInfo(("Reserved heap size: %lu\r\n", heap_stats.reserved_size));
            #endif            
            /* Activate the new firmware image. */
            OTA_ActivateNewImage();

            /* Shutdown OTA Agent. */
            OTA_Shutdown( 0 );

            /* Requires manual activation of new image.*/
            LogError( ( "New image activation failed." ) );

            break;

        case OtaJobEventFail:
            LogInfo( ( "Received OtaJobEventFail callback from OTA Agent." ) );

            /* Nothing special to do. The OTA agent handles it. */
            break;

        case OtaJobEventStartTest:

            /* This demo just accepts the image since it was a good OTA update and networking
             * and services are all working (or we would not have made it this far). If this
             * were some custom device that wants to test other things before validating new
             * image, this would be the place to kick off those tests before calling
             * OTA_SetImageState() with the final result of either accepted or rejected. */

            LogInfo( ( "Received OtaJobEventStartTest callback from OTA Agent." ) );
            err = OTA_SetImageState( OtaImageStateAccepted );

            if( err != OtaErrNone )
            {
                LogError( ( " Failed to set image state as accepted." ) );
            }

            break;

        case OtaJobEventProcessed:
            LogDebug( ( "Received OtaJobEventProcessed callback from OTA Agent." ) );

            if( pData != NULL )
            {
                otaEventBufferFree( ( OtaEventData_t * ) pData );
            }

            break;

        case OtaJobEventSelfTestFailed:
            LogDebug( ( "Received OtaJobEventSelfTestFailed callback from OTA Agent." ) );

            /* Requires manual activation of previous image as self-test for
             * new image downloaded failed.*/
            LogError( ( "Self-test failed, shutting down OTA Agent." ) );

            /* Shutdown OTA Agent. */
            OTA_Shutdown( 0 );


            break;

        default:
            LogDebug( ( "Received invalid callback event from OTA Agent." ) );
    }
}

/*-----------------------------------------------------------*/

static void mqttJobCallback( MQTTContext_t * pContext,
                             MQTTPublishInfo_t * pPublishInfo )
{
    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    assert( pPublishInfo != NULL );
    assert( pContext != NULL );

    ( void ) pContext;

    LogInfo( ( "Received job message callback, size %d.\n\n", pPublishInfo->payloadLength ) );

    pData = otaEventBufferGet();

    if( pData != NULL )
    {
        memcpy( pData->data, pPublishInfo->pPayload, pPublishInfo->payloadLength );
        pData->dataLength = pPublishInfo->payloadLength;
        eventMsg.eventId = OtaAgentEventReceivedJobDocument;
        eventMsg.pEventData = pData;

        /* Send job document received event. */
        OTA_SignalEvent( &eventMsg );
    }
    else
    {
        LogError( ( "No OTA data buffers available." ) );
    }
}

/*-----------------------------------------------------------*/

static void mqttDataCallback( MQTTContext_t * pContext,
                              MQTTPublishInfo_t * pPublishInfo )
{
    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    assert( pPublishInfo != NULL );
    assert( pContext != NULL );

    ( void ) pContext;

    LogInfo( ( "Received data message callback, size %zu.\n\n", pPublishInfo->payloadLength ) );

    pData = otaEventBufferGet();

    if( pData != NULL )
    {
        memcpy( pData->data, pPublishInfo->pPayload, pPublishInfo->payloadLength );
        pData->dataLength = pPublishInfo->payloadLength;
        eventMsg.eventId = OtaAgentEventReceivedFileBlock;
        eventMsg.pEventData = pData;

        /* Send job document received event. */
        OTA_SignalEvent( &eventMsg );
    }
    else
    {
        LogError( ( "No OTA data buffers available." ) );
    }
}

/*-----------------------------------------------------------*/

static void mqttEventCallback( MQTTContext_t * pMqttContext,
                               MQTTPacketInfo_t * pPacketInfo,
                               MQTTDeserializedInfo_t * pDeserializedInfo )
{
    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );
    assert( pDeserializedInfo != NULL );

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        assert( pDeserializedInfo->pPublishInfo != NULL );
        /* Handle incoming publish. */
        SubscriptionManager_DispatchHandler( pMqttContext, pDeserializedInfo->pPublishInfo );
    }
    else
    {
        /* Handle other packets. */
        switch( pPacketInfo->type )
        {
            case MQTT_PACKET_TYPE_SUBACK:
                LogInfo( ( "Received SUBACK.\n\n" ) );
                break;

            case MQTT_PACKET_TYPE_UNSUBACK:
                LogInfo( ( "Received UNSUBACK.\n\n" ) );
                break;

            case MQTT_PACKET_TYPE_PINGRESP:

                /* Nothing to be done from application as library handles
                 * PINGRESP. */
                LogWarn( ( "PINGRESP should not be handled by the application "
                           "callback when using MQTT_ProcessLoop.\n\n" ) );
                break;

            case MQTT_PACKET_TYPE_PUBACK:
                LogInfo( ( "PUBACK received for packet id %u.\n\n",
                           pDeserializedInfo->packetIdentifier ) );
                break;

            /* Any other packet type is invalid. */
            default:
                LogError( ( "Unknown packet type received:(%02x).\n\n",
                            pPacketInfo->type ) );
        }
    }
}

/*-----------------------------------------------------------*/

static uint32_t generateRandomNumber()
{
    return( rand() );
}

/*-----------------------------------------------------------*/

static int initializeMqtt( MQTTContext_t * pMqttContext,
                           NetworkContext_t * pNetworkContext )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus;
    MQTTFixedBuffer_t networkBuffer;
    TransportInterface_t transport;

    assert( pMqttContext != NULL );
    assert( pNetworkContext != NULL );

    /* Fill in TransportInterface send and receive function pointers.
     * For this demo, TCP sockets are used to send and receive data
     * from network.  TLS over TCP channel is used as the transport
     * layer for the MQTT connection. Network context is SSL context
     * for Mbed TLSSocket.*/
    transport.pNetworkContext = pNetworkContext;
    transport.send = Mbed_Tls_Send;
    transport.recv = Mbed_Tls_Recv;

    /* Fill the values for network buffer. */
    networkBuffer.pBuffer = otaNetworkBuffer;
    networkBuffer.size = OTA_NETWORK_BUFFER_SIZE;

    /* Initialize MQTT library. */
    mqttStatus = MQTT_Init( pMqttContext,
                            &transport,
                            Clock_GetTimeMs,
                            mqttEventCallback,
                            &networkBuffer );

    if( mqttStatus != MQTTSuccess )
    {
        returnStatus = EXIT_FAILURE;
        LogError( ( "MQTT init failed: Status = %s.", MQTT_Status_strerror( mqttStatus ) ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int connectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext )
{
    int returnStatus = EXIT_SUCCESS;
    BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
    int32_t tls_conn_status = 0;
    BackoffAlgorithmContext_t reconnectParams;
    ServerInfo_t serverInfo = {};
    CredentialInfo_t credentialInfo = {};
    uint16_t nextRetryBackOff;

    /* Initialize information to connect to the MQTT broker. */
    serverInfo.hostname = AWS_IOT_ENDPOINT;
    serverInfo.port = AWS_MQTT_PORT;

    /* Initialize credentials for establishing TLS session. */
    memset( &credentialInfo, 0, sizeof( CredentialInfo_t ) );
    //opensslCredentials.pRootCaPath = ROOT_CA_CERT_PATH;
    credentialInfo.rootCA = aws::credentials::provision::rootCACrt();

    /* If #CLIENT_USERNAME is defined, username/password is used for authenticating
     * the client. */
    #ifndef CLIENT_USERNAME
        //opensslCredentials.pClientCertPath = CLIENT_CERT_PATH;
        //opensslCredentials.pPrivateKeyPath = CLIENT_PRIVATE_KEY_PATH;
        credentialInfo.clientCrt = aws::credentials::provision::deviceCrt();
        credentialInfo.clientKey = aws::credentials::provision::devicePvtKey();
    #endif

    /* AWS IoT requires devices to send the Server Name Indication (SNI)
     * extension to the Transport Layer Security (TLS) protocol and provide
     * the complete endpoint address in the host_name field. Details about
     * SNI for AWS IoT can be found in the link below.
     * https://docs.aws.amazon.com/iot/latest/developerguide/transport-security.html */
    /* In Mbed port, this is passed to TLSSocket via serverInfo */
    //opensslCredentials.sniHostName = AWS_IOT_ENDPOINT;

    if( AWS_MQTT_PORT == 443 )
    {
        /* Pass the ALPN protocol name depending on the port being used.
         * Please see more details about the ALPN protocol for the AWS IoT MQTT
         * endpoint in the link below.
         * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
         *
         * For username and password based authentication in AWS IoT,
         * #AWS_IOT_PASSWORD_ALPN is used. More details can be found in the
         * link below.
         * https://docs.aws.amazon.com/iot/latest/developerguide/enhanced-custom-auth-using.html
         */
        #ifdef CLIENT_USERNAME
            //opensslCredentials.pAlpnProtos = AWS_IOT_PASSWORD_ALPN;
            //opensslCredentials.alpnProtosLen = AWS_IOT_PASSWORD_ALPN_LENGTH;
            /* Check mbedtls API mbedtls_ssl_conf_alpn_protocols(...) for format and lifetime of the alpnProtos table */
            static const char *alpnProtos[] = {
                AWS_IOT_PASSWORD_ALPN,
                NULL
            };
            credentialInfo.alpnProtos = alpnProtos;
        #else
            //opensslCredentials.pAlpnProtos = AWS_IOT_MQTT_ALPN;
            //opensslCredentials.alpnProtosLen = AWS_IOT_MQTT_ALPN_LENGTH;
            /* Same requirements as above for alpnProtos */
            static const char *alpnProtos[] = {
                AWS_IOT_MQTT_ALPN,
                NULL
            };
            credentialInfo.alpnProtos = alpnProtos;
        #endif
    }

    /* Initialize reconnect attempts and interval */
    BackoffAlgorithm_InitializeParams( &reconnectParams,
                                       CONNECTION_RETRY_BACKOFF_BASE_MS,
                                       CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
                                       CONNECTION_RETRY_MAX_ATTEMPTS );

    /* Attempt to connect to MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will exponentially increase until maximum
     * attempts are reached.
     */
    do
    {
        /* Establish a TLS session with the MQTT broker. This example connects
         * to the MQTT broker as specified in AWS_IOT_ENDPOINT and AWS_MQTT_PORT
         * at the demo config header. */
        LogInfo( ( "Establishing a TLS session to %.*s:%d.",
                   AWS_IOT_ENDPOINT_LENGTH,
                   AWS_IOT_ENDPOINT,
                   AWS_MQTT_PORT ) );
        tls_conn_status = Mbed_Tls_Connect(pNetworkContext,
                                            &serverInfo,
                                            &credentialInfo,
                                            TRANSPORT_SEND_RECV_TIMEOUT_MS,
                                            TRANSPORT_SEND_RECV_TIMEOUT_MS);
                                            
        if( tls_conn_status != 0 )
        {
            /* Generate a random number and get back-off value (in milliseconds) for the next connection retry. */
            backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &reconnectParams, generateRandomNumber(), &nextRetryBackOff );

            if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
            {
                LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
                returnStatus = EXIT_FAILURE;
            }
            else if( backoffAlgStatus == BackoffAlgorithmSuccess )
            {
                LogWarn( ( "Connection to the broker failed. Retrying connection "
                           "after %hu ms backoff.",
                           ( unsigned short ) nextRetryBackOff ) );
                Clock_SleepMs( nextRetryBackOff );
            }
        }
    } while( ( tls_conn_status != 0 ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int establishMqttSession( MQTTContext_t * pMqttContext )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTConnectInfo_t connectInfo = { 0 };

    bool sessionPresent = false;

    assert( pMqttContext != NULL );

    /* Establish MQTT session by sending a CONNECT packet. */

    /* If #createCleanSession is true, start with a clean session
     * i.e. direct the MQTT broker to discard any previous session data.
     * If #createCleanSession is false, directs the broker to attempt to
     * reestablish a session which was already present. */
    connectInfo.cleanSession = true;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    connectInfo.pClientIdentifier = CLIENT_IDENTIFIER;
    connectInfo.clientIdentifierLength = CLIENT_IDENTIFIER_LENGTH;

    /* The maximum time interval in seconds which is allowed to elapse
     * between two Control Packets.
     * It is the responsibility of the Client to ensure that the interval between
     * Control Packets being sent does not exceed the this Keep Alive value. In the
     * absence of sending any other Control Packets, the Client MUST send a
     * PINGREQ Packet. */
    connectInfo.keepAliveSeconds = MQTT_KEEP_ALIVE_INTERVAL_SECONDS;

    /* Use the username and password for authentication, if they are defined.
     * Refer to the AWS IoT documentation below for details regarding client
     * authentication with a username and password.
     * https://docs.aws.amazon.com/iot/latest/developerguide/enhanced-custom-authentication.html
     * An authorizer setup needs to be done, as mentioned in the above link, to use
     * username/password based client authentication.
     *
     * The username field is populated with voluntary metrics to AWS IoT.
     * The metrics collected by AWS IoT are the operating system, the operating
     * system's version, the hardware platform, and the MQTT Client library
     * information. These metrics help AWS IoT improve security and provide
     * better technical support.
     *
     * If client authentication is based on username/password in AWS IoT,
     * the metrics string is appended to the username to support both client
     * authentication and metrics collection. */
    #ifdef CLIENT_USERNAME
        connectInfo.pUserName = CLIENT_USERNAME_WITH_METRICS;
        connectInfo.userNameLength = strlen( CLIENT_USERNAME_WITH_METRICS );
        connectInfo.pPassword = CLIENT_PASSWORD;
        connectInfo.passwordLength = strlen( CLIENT_PASSWORD );
    #else
        connectInfo.pUserName = METRICS_STRING;
        connectInfo.userNameLength = METRICS_STRING_LENGTH;
        /* Password for authentication is not used. */
        connectInfo.pPassword = NULL;
        connectInfo.passwordLength = 0U;
    #endif /* ifdef CLIENT_USERNAME */

    mqttMutex.lock();
    {
        /* Send MQTT CONNECT packet to broker. */
        mqttStatus = MQTT_Connect( pMqttContext, &connectInfo, NULL, CONNACK_RECV_TIMEOUT_MS, &sessionPresent );
    }
    mqttMutex.unlock();

    if( mqttStatus != MQTTSuccess )
    {
        returnStatus = EXIT_FAILURE;
        LogError( ( "Connection with MQTT broker failed with status %s.",
                    MQTT_Status_strerror( mqttStatus ) ) );
    }
    else
    {
        LogInfo( ( "MQTT connection successfully established with broker.\n\n" ) );
#if MBED_HEAP_STATS_ENABLED
        mbed_stats_heap_get(&heap_stats);
        LogInfo(("Current heap: %lu\r\n", heap_stats.current_size));
        LogInfo(("Max heap size: %lu\r\n", heap_stats.max_size));
        LogInfo(("Reserved heap size: %lu\r\n", heap_stats.reserved_size));
#endif            
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int establishConnection( void )
{
    int returnStatus = EXIT_FAILURE;

    /* Attempt to connect to the MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will be exponentially increased till the maximum
     * attempts are reached or maximum timeout value is reached. The function
     * returns EXIT_FAILURE if the TCP connection cannot be established to
     * broker after configured number of attempts. */
    returnStatus = connectToServerWithBackoffRetries( &networkContext );

    if( returnStatus != EXIT_SUCCESS )
    {
        /* Log error to indicate connection failure. */
        LogError( ( "Failed to connect to MQTT broker %.*s.",
                    AWS_IOT_ENDPOINT_LENGTH,
                    AWS_IOT_ENDPOINT ) );
    }
    else
    {
        /* Establish MQTT session on top of TCP+TLS connection. */
        LogInfo( ( "Creating an MQTT connection to %.*s.",
                   AWS_IOT_ENDPOINT_LENGTH,
                   AWS_IOT_ENDPOINT ) );

        /* Sends an MQTT Connect packet using the established TLS session,
         * then waits for connection acknowledgment (CONNACK) packet. */
        returnStatus = establishMqttSession( &mqttContext );

        if( returnStatus != EXIT_SUCCESS )
        {
            LogError( ( "Failed creating an MQTT connection to %.*s.",
                        AWS_IOT_ENDPOINT_LENGTH,
                        AWS_IOT_ENDPOINT ) );
        }
        else
        {
            LogDebug( ( "Success creating MQTT connection to %.*s.",
                        AWS_IOT_ENDPOINT_LENGTH,
                        AWS_IOT_ENDPOINT ) );

            mqttSessionEstablished = true;
        }
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static void disconnect( void )
{
    /* Disconnect from broker. */
    LogInfo( ( "Disconnecting the MQTT connection with %s.", AWS_IOT_ENDPOINT ) );

    if( mqttSessionEstablished == true )
    {
        mqttMutex.lock();
        {
            /* Disconnect MQTT session. */
            MQTT_Disconnect( &mqttContext );

            /* Clear the mqtt session flag. */
            mqttSessionEstablished = false;
        }
        mqttMutex.unlock();
    }
    else
    {
        LogError( ( "MQTT already disconnected." ) );
    }

    /* End TLS session, then close TCP connection. */
    ( void ) Mbed_Tls_Disconnect( &networkContext );
}

/*-----------------------------------------------------------*/

static OtaMessageType_t getOtaMessageType( const char * pTopicFilter,
                                           uint16_t topicFilterLength )
{
    int retStatus = EXIT_FAILURE;

    uint16_t stringIndex = 0U, fieldLength = 0U, i = 0U;
    OtaMessageType_t retMesageType = OtaNumOfMessageType;

    /* Lookup table for OTA message string. */
    static const char * const pOtaMessageStrings[ OtaNumOfMessageType ] =
    {
        OTA_TOPIC_JOBS,
        OTA_TOPIC_STREAM
    };

    /* Check topic prefix is valid.*/
    if( strncmp( pTopicFilter, OTA_TOPIC_PREFIX, ( size_t ) OTA_TOPIC_PREFIX_LENGTH ) == 0 )
    {
        stringIndex = OTA_TOPIC_PREFIX_LENGTH;

        retStatus = EXIT_SUCCESS;
    }

    /* Check if thing name is valid.*/
    if( retStatus == EXIT_SUCCESS )
    {
        retStatus = EXIT_FAILURE;

        /* Extract the thing name.*/
        for( ; stringIndex < topicFilterLength; stringIndex++ )
        {
            if( pTopicFilter[ stringIndex ] == ( char ) '/' )
            {
                break;
            }
            else
            {
                fieldLength++;
            }
        }

        if( fieldLength > 0 )
        {
            /* Check thing name.*/
            if( strncmp( &pTopicFilter[ stringIndex - fieldLength ],
                         THING_NAME,
                         ( size_t ) ( fieldLength ) ) == 0 )
            {
                stringIndex++;

                retStatus = EXIT_SUCCESS;
            }
        }
    }

    /* Check the message type from topic.*/
    if( retStatus == EXIT_SUCCESS )
    {
        fieldLength = 0;

        /* Extract the topic type.*/
        for( ; stringIndex < topicFilterLength; stringIndex++ )
        {
            if( pTopicFilter[ stringIndex ] == ( char ) '/' )
            {
                break;
            }
            else
            {
                fieldLength++;
            }
        }

        if( fieldLength > 0 )
        {
            for( i = 0; i < OtaNumOfMessageType; i++ )
            {
                /* check thing name.*/
                if( strncmp( &pTopicFilter[ stringIndex - fieldLength ],
                             pOtaMessageStrings[ i ],
                             ( size_t ) ( fieldLength ) ) == 0 )
                {
                    break;
                }
            }

            if( i < OtaNumOfMessageType )
            {
                retMesageType = (OtaMessageType_t) i;
            }
        }
    }

    return retMesageType;
}

/*-----------------------------------------------------------*/

static OtaMqttStatus_t mqttSubscribe( const char * pTopicFilter,
                                      uint16_t topicFilterLength,
                                      uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;
    SubscriptionManagerStatus_t subscriptionStatus = SUBSCRIPTION_MANAGER_SUCCESS;
    OtaMessageType_t otaMessageType;

    MQTTStatus_t mqttStatus;
    MQTTContext_t * pMqttContext = &mqttContext;
    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];

    assert( pMqttContext != NULL );
    assert( pTopicFilter != NULL );
    assert( topicFilterLength > 0 );

    ( void ) qos;

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    /* Set the topic and topic length. */
    pSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    mqttMutex.lock();
    {
        /* Send SUBSCRIBE packet. */
        mqttStatus = MQTT_Subscribe( pMqttContext,
                                     pSubscriptionList,
                                     sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                     MQTT_GetPacketId( pMqttContext ) );
    }
    mqttMutex.unlock();

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %u.",
                    mqttStatus ) );

        otaRet = OtaMqttSubscribeFailed;
    }
    else
    {
        LogInfo( ( "SUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );
    }

    otaMessageType = getOtaMessageType( pTopicFilter, topicFilterLength );

    assert( ( otaMessageType >= 0 ) && ( otaMessageType < OtaNumOfMessageType ) );

    /* Register callback to subscription manager. */
    subscriptionStatus = SubscriptionManager_RegisterCallback( pTopicFilter,
                                                               topicFilterLength,
                                                               otaMessageCallback[ otaMessageType ] );

    if( subscriptionStatus != SUBSCRIPTION_MANAGER_SUCCESS )
    {
        LogWarn( ( "Failed to register a callback to subscription manager with error = %d.",
                   subscriptionStatus ) );
    }

    return otaRet;
}

/*-----------------------------------------------------------*/

static OtaMqttStatus_t mqttPublish( const char * const pacTopic,
                                    uint16_t topicLen,
                                    const char * pMsg,
                                    uint32_t msgSize,
                                    uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;

    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTPublishInfo_t publishInfo = {};
    MQTTContext_t * pMqttContext = &mqttContext;

    /* Set the required publish parameters. */
    publishInfo.pTopicName = pacTopic;
    publishInfo.topicNameLength = topicLen;
    publishInfo.qos = (MQTTQoS_t) qos;
    publishInfo.pPayload = pMsg;
    publishInfo.payloadLength = msgSize;

    mqttMutex.lock();
    {
        mqttStatus = MQTT_Publish( pMqttContext,
                                   &publishInfo,
                                   MQTT_GetPacketId( pMqttContext ) );
    }
    mqttMutex.unlock();

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send PUBLISH packet to broker with error = %u.", mqttStatus ) );

        otaRet = OtaMqttPublishFailed;
    }
    else
    {
        LogInfo( ( "Sent PUBLISH packet to broker %.*s to broker.\n\n",
                   topicLen,
                   pacTopic ) );
    }

    return otaRet;
}

/*-----------------------------------------------------------*/

static OtaMqttStatus_t mqttUnsubscribe( const char * pTopicFilter,
                                        uint16_t topicFilterLength,
                                        uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;
    MQTTStatus_t mqttStatus = MQTTBadParameter;

    MQTTSubscribeInfo_t pSubscriptionList[ 1 ];
    MQTTContext_t * pMqttContext = &mqttContext;

    ( void ) qos;

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pSubscriptionList, 0x00, sizeof( pSubscriptionList ) );

    /* Set the topic and topic length. */
    pSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    mqttMutex.lock();
    {
        /* Send UNSUBSCRIBE packet. */
        mqttStatus = MQTT_Unsubscribe( pMqttContext,
                                       pSubscriptionList,
                                       sizeof( pSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                       MQTT_GetPacketId( pMqttContext ) );
    }
    mqttMutex.unlock();

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %u.",
                    mqttStatus ) );

        otaRet = OtaMqttUnsubscribeFailed;
    }
    else
    {
        LogInfo( ( "SUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );
    }

    return otaRet;
}

/*-----------------------------------------------------------*/

static void setOtaInterfaces( OtaInterfaces_t * pOtaInterfaces )
{
    /* Initialize OTA library OS Interface. */
    pOtaInterfaces->os.event.init = Mbed_OtaInitEvent;
    pOtaInterfaces->os.event.send = Mbed_OtaSendEvent;
    pOtaInterfaces->os.event.recv = Mbed_OtaReceiveEvent;
    pOtaInterfaces->os.event.deinit = Mbed_OtaDeinitEvent;
    pOtaInterfaces->os.timer.start = Mbed_OtaStartTimer;
    pOtaInterfaces->os.timer.stop = Mbed_OtaStopTimer;
    /* Get around C++ reserved keyword 'delete' used in OtaTimerInterface_t
     * (ota_os_interface.h) as above */
    #define delete  delete_
    pOtaInterfaces->os.timer.delete = Mbed_OtaDeleteTimer;
    #undef delete
    pOtaInterfaces->os.mem.malloc = STDC_Malloc;
    pOtaInterfaces->os.mem.free = STDC_Free;

    /* Initialize the OTA library MQTT Interface.*/
    pOtaInterfaces->mqtt.subscribe = mqttSubscribe;
    pOtaInterfaces->mqtt.publish = mqttPublish;
    pOtaInterfaces->mqtt.unsubscribe = mqttUnsubscribe;

    /* Initialize the OTA library PAL Interface.*/
    pOtaInterfaces->pal.getPlatformImageState = otaPal_GetPlatformImageState;
    pOtaInterfaces->pal.setPlatformImageState = otaPal_SetPlatformImageState;
    pOtaInterfaces->pal.writeBlock = otaPal_WriteBlock;
    pOtaInterfaces->pal.activate = otaPal_ActivateNewImage;
    pOtaInterfaces->pal.closeFile = otaPal_CloseFile;
    pOtaInterfaces->pal.reset = otaPal_ResetDevice;
    pOtaInterfaces->pal.abort = otaPal_Abort;
    pOtaInterfaces->pal.createFile = otaPal_CreateFileForRx;
}

/*-----------------------------------------------------------*/

static void otaThread( void * pParam )
{
    /* Calling OTA agent task. */
    OTA_EventProcessingTask( pParam );
    LogInfo( ( "OTA Agent stopped." ) );
}
/*-----------------------------------------------------------*/
static int startOTADemo( void )
{
    /* Status indicating a successful demo or not. */
    int returnStatus = EXIT_SUCCESS;

    /* coreMQTT library return status. */
    MQTTStatus_t mqttStatus = MQTTBadParameter;

    /* OTA library return status. */
    OtaErr_t otaRet = OtaErrNone;

    /* OTA Agent state returned from calling OTA_GetAgentState.*/
    OtaState_t state = OtaAgentStateStopped;

    /* OTA event message used for sending event to OTA Agent.*/
    OtaEventMsg_t eventMsg = { 0 };

    /* OTA library packet statistics per job.*/
    OtaAgentStatistics_t otaStatistics = { 0 };

    /* OTA interface context required for library interface functions.*/
    OtaInterfaces_t otaInterfaces;

    /* Maximum time to wait for the OTA agent to get suspended. */
    int16_t suspendTimeout;

    /* Set OTA Library interfaces.*/
    setOtaInterfaces( &otaInterfaces );

    LogInfo( ( "OTA over MQTT demo, Application version %u.%u.%u",
               appFirmwareVersion.u.x.major,
               appFirmwareVersion.u.x.minor,
               appFirmwareVersion.u.x.build ) );

    /****************************** Init OTA Library. ******************************/

    if( returnStatus == EXIT_SUCCESS )
    {
        if( ( otaRet = OTA_Init( &otaBuffer,
                                 &otaInterfaces,
                                 ( const uint8_t * ) ( THING_NAME ),
                                 otaAppCallback ) ) != OtaErrNone )
        {
            LogError( ( "Failed to initialize OTA Agent, exiting = %u.",
                        otaRet ) );

            returnStatus = EXIT_FAILURE;
        }
    }

    /****************************** Create OTA Task. ******************************/

    if( returnStatus == EXIT_SUCCESS )
    {   
        auto os_status = otaAgentThread.start(callback(otaThread, (void*)NULL));
        if (os_status != osOK)
        {
            LogError( ( "Failed to create OTA thread: "
                        "osStatus: %d",
                        os_status ) );

            returnStatus = EXIT_FAILURE;
        }
    }

    /****************************** OTA Demo loop. ******************************/

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Wait till OTA library is stopped, output statistics for currently running
         * OTA job */
        while( ( ( state = OTA_GetState() ) != OtaAgentStateStopped ) )
        {
            if( mqttSessionEstablished != true )
            {
                /* Connect to MQTT broker and create MQTT connection. */
                returnStatus = establishConnection();

                if( returnStatus == EXIT_SUCCESS )
                {
                    /* Check if OTA process was suspended and resume if required. */
                    if( state == OtaAgentStateSuspended )
                    {
                        /* Resume OTA operations. */
                        OTA_Resume();
                    }
                    else
                    {
                        /* Send start event to OTA Agent.*/
                        eventMsg.eventId = OtaAgentEventStart;
                        OTA_SignalEvent( &eventMsg );
                    }
                }
            }

            if( mqttSessionEstablished == true )
            {
                /* Acquire the mqtt mutex lock. */
                mqttMutex.lock();
                {
                    /* Loop to receive packet from transport interface. */
                    mqttStatus = MQTT_ProcessLoop( &mqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS );
                }
                mqttMutex.unlock();

                if( mqttStatus == MQTTSuccess )
                {
                    /* Get OTA statistics for currently executing job. */
                    OTA_GetStatistics( &otaStatistics );

                    LogInfo( ( " Received: %u   Queued: %u   Processed: %u   Dropped: %u",
                               otaStatistics.otaPacketsReceived,
                               otaStatistics.otaPacketsQueued,
                               otaStatistics.otaPacketsProcessed,
                               otaStatistics.otaPacketsDropped ) );

                    /* Delay if mqtt process loop is set to zero.*/
                    if( !( MQTT_PROCESS_LOOP_TIMEOUT_MS > 0 ) )
                    {
                        Clock_SleepMs( OTA_EXAMPLE_LOOP_SLEEP_PERIOD_MS );
                    }
                }
                else
                {
                    LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                                MQTT_Status_strerror( mqttStatus ) ) );

                    /* Disconnect from broker and close connection. */
                    disconnect();

                    /* Suspend OTA operations. */
                    otaRet = OTA_Suspend();

                    if( otaRet == OtaErrNone )
                    {
                        suspendTimeout = OTA_SUSPEND_TIMEOUT_MS;

                        while( ( ( state = OTA_GetState() ) != OtaAgentStateSuspended ) && ( suspendTimeout > 0 ) )
                        {
                            /* Wait for OTA Library state to suspend */
                            Clock_SleepMs( OTA_EXAMPLE_TASK_DELAY_MS );
                            suspendTimeout -= OTA_EXAMPLE_TASK_DELAY_MS;
                        }
                    }
                    else
                    {
                        LogError( ( "OTA failed to suspend. "
                                    "StatusCode=%d.", otaRet ) );
                    }
                }
            }
        }
    }

    return returnStatus;
}

#if MBED_CONF_AWS_CLIENT_LOG_RETARGET

/* Synchronize log output with mutex
 *
 * We can use the same mutex to synchronize log output across all AWS IoT SDK
 * and mbed trace, if enabled.
 */
static Mutex log_mutex;

#if MBED_CONF_MBED_TRACE_ENABLE

#define TRACE_GROUP "Main"

static void trace_mutex_lock()
{
    log_mutex.lock();
}
static void trace_mutex_unlock()
{
    log_mutex.unlock();
}

#endif

extern "C" void aws_iot_log_printf(const char * format, ...) {
    log_mutex.lock();
    va_list args;
    va_start (args, format);
    vprintf(format, args);
    va_end (args);
    log_mutex.unlock();
}

#endif

/*-----------------------------------------------------------*/

/**
 * @brief Entry point of demo.
 *
 * This example initializes the OTA library to enable OTA updates via the
 * MQTT broker. It simply connects to the MQTT broker with the users
 * credentials and spins in an indefinite loop to allow MQTT messages to be
 * forwarded to the OTA agent for possible processing. The OTA agent does all
 * of the real work; checking to see if the message topic is one destined for
 * the OTA agent. If not, it is simply ignored.
 */
int main()
{
#if MBED_CONF_MBED_TRACE_ENABLE
    mbed_trace_mutex_wait_function_set( trace_mutex_lock ); // only if thread safety is needed
    mbed_trace_mutex_release_function_set( trace_mutex_unlock ); // only if thread safety is needed
    mbed_trace_init();
#endif

    LogInfo( ("*** Application version: %d.%d.%d", APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_BUILD) );
    LogInfo( ("Connecting to the network...") );
    auto net = NetworkInterface::get_default_instance();
    if (net == NULL) {
        LogError( ("No Network interface found.") );
        return -1;
    }
    auto ret = net->connect();
    if (ret != 0) {
        LogError( ("Connection error: %x", ret) );
        return -1;
    }
    LogInfo( ("MAC: %s", net->get_mac_address()) );
    LogInfo( ("Connection Success") );
#if MBED_HEAP_STATS_ENABLED
    mbed_stats_heap_get(&heap_stats);
    LogInfo(("Current heap: %lu\r\n", heap_stats.current_size));
    LogInfo(("Max heap size: %lu\r\n", heap_stats.max_size));
    LogInfo(("Reserved heap size: %lu\r\n", heap_stats.reserved_size));
#endif            
    /* Return error status. */
    int returnStatus = EXIT_SUCCESS;

    /* Maximum time in milliseconds to wait before exiting demo . */
    int16_t waitTimeoutMs = OTA_DEMO_EXIT_TIMEOUT_MS;

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Initialize MQTT library. Initialization of the MQTT library needs to be
         * done only once in this demo. */
        returnStatus = initializeMqtt( &mqttContext, &networkContext );
    }

    if( returnStatus == EXIT_SUCCESS )
    {
        /* Start OTA demo. */
        returnStatus = startOTADemo();
    }

    /* Disconnect from broker and close connection. */
    disconnect();

    /* Wait and log message before exiting demo. */
    while( waitTimeoutMs > 0 )
    {
        Clock_SleepMs( OTA_EXAMPLE_TASK_DELAY_MS );
        waitTimeoutMs -= OTA_EXAMPLE_TASK_DELAY_MS;

        LogError( ( "Exiting demo in %d sec", waitTimeoutMs / 1000 ) );
    }

    return returnStatus;
}
