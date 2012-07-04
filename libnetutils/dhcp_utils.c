/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 *     http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

/* Utilities for managing the dhcpcd DHCP client daemon */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cutils/properties.h>

static const char DAEMON_NAME[]        = "dhcpcd";
static const char DAEMON_PROP_NAME[]   = "init.svc.dhcpcd";
static const char HOSTNAME_PROP_NAME[] = "net.hostname";
static const char DHCP_PROP_NAME_PREFIX[]  = "dhcp";
static const int NAP_TIME = 200;   /* wait for 200ms at a time */
                                  /* when polling for property values */
static const char DAEMON_NAME_RENEW[]  = "iprenew";
static char errmsg[100];

#ifdef USE_MOTOROLA_CODE
//BEGIN MOT ICS UPMERGE, w20079, Nov 22, 2011
//IKHALFMWK-192 USB Ethernet feature 35480, Motorola, e7976c, 01/13/2011
static int autoip_enabled[3] = {0, 0, 0};//WiFi, Bluetooth, Ethernet
//END MOT ICS UPMERGE
#endif

/* interface suffix on dhcpcd */
#define MAX_DAEMON_SUFFIX 25

/*
 * Wait for a system property to be assigned a specified value.
 * If desired_value is NULL, then just wait for the property to
 * be created with any value. maxwait is the maximum amount of
 * time in seconds to wait before giving up.
 */
static int wait_for_property(const char *name, const char *desired_value, int maxwait)
{
    char value[PROPERTY_VALUE_MAX] = {'\0'};
    int maxnaps = (maxwait * 1000) / NAP_TIME;

    if (maxnaps < 1) {
        maxnaps = 1;
    }

    while (maxnaps-- > 0) {
        usleep(NAP_TIME * 1000);
        if (property_get(name, value, NULL)) {
            if (desired_value == NULL || 
                    strcmp(value, desired_value) == 0) {
                return 0;
            }
        }
    }
    return -1; /* failure */
}

static int fill_ip_info(const char *interface,
                     char *ipaddr,
                     char *gateway,
                     uint32_t *prefixLength,
                     char *dns1,
                     char *dns2,
                     char *server,
                     uint32_t  *lease)
{
    char prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX];

    snprintf(prop_name, sizeof(prop_name), "%s.%s.ipaddress", DHCP_PROP_NAME_PREFIX, interface);
    property_get(prop_name, ipaddr, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.gateway", DHCP_PROP_NAME_PREFIX, interface);
    property_get(prop_name, gateway, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.server", DHCP_PROP_NAME_PREFIX, interface);
    property_get(prop_name, server, NULL);

    //TODO: Handle IPv6 when we change system property usage
    if (strcmp(gateway, "0.0.0.0") == 0) {
        //DHCP server is our best bet as gateway
        strncpy(gateway, server, PROPERTY_VALUE_MAX);
    }

    snprintf(prop_name, sizeof(prop_name), "%s.%s.mask", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL)) {
        int p;
        // this conversion is v4 only, but this dhcp client is v4 only anyway
        in_addr_t mask = ntohl(inet_addr(prop_value));
        // Check netmask is a valid IP address.  ntohl gives NONE response (all 1's) for
        // non 255.255.255.255 inputs.  if we get that value check if it is legit..
        if (mask == INADDR_NONE && strcmp(prop_value, "255.255.255.255") != 0) {
            snprintf(errmsg, sizeof(errmsg), "DHCP gave invalid net mask %s", prop_value);
            return -1;
        }
        for (p = 0; p < 32; p++) {
            if (mask == 0) break;
            // check for non-contiguous netmask, e.g., 255.254.255.0
            if ((mask & 0x80000000) == 0) {
                snprintf(errmsg, sizeof(errmsg), "DHCP gave invalid net mask %s", prop_value);
                return -1;
            }
            mask = mask << 1;
        }
        *prefixLength = p;

#ifdef USE_MOTOROLA_CODE
    //BEGIN MOT ICS UPMERGE, w20079, Nov 22, 2011
    //Begin Motorola w20079 IKTABLETMAIN-3679 Force close on wifi browser test
    } else {
        *prefixLength = 0;
    //END MOT ICS UPMERGE
#endif

    }
    snprintf(prop_name, sizeof(prop_name), "%s.%s.dns1", DHCP_PROP_NAME_PREFIX, interface);
    property_get(prop_name, dns1, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.dns2", DHCP_PROP_NAME_PREFIX, interface);
    property_get(prop_name, dns2, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.leasetime", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL)) {
        *lease = atol(prop_value);
    }
    return 0;
}

#ifdef USE_MOTOROLA_CODE
// BEGIN MOT ICS UPMERGE, w20079, Nov 22, 2011
// BEGIN MOT, w20079, Jan-15-2010, IKMAPFOUR-28 / Changed for auto ip feature
static int get_device_type(const char * interface)
{
    //tiwlan0 and eth0 means WiFi
    if( strcmp(interface, "tiwlan0") == 0 || strcmp(interface, "eth0") == 0 || strncmp(interface, "wlan", 4) == 0 ) {
        return 0;
    } else if( strcmp(interface, "bnep0") == 0 ) {
        return 1;
    //BEGIN Motorola, e7976c, 01/13/2011, IKHALFMWK-192:feature 35480: Support for USB to Ethernet adaptor through Olympus HD Dock
    } else if( strcmp(interface, "usbeth0") == 0 ) {
        return 2;
    //END Motorola, e7976c, 01/13/2011, IKHALFMWK-192:feature 35480
    } else {
        //unknow type
        return -1;
    }
}
//END MOT ICS UPMERGE
#endif

static const char *ipaddr_to_string(in_addr_t addr)
{
    struct in_addr in_addr;

    in_addr.s_addr = addr;
    return inet_ntoa(in_addr);
}

void get_daemon_suffix(const char *interface, char *daemon_suffix) {
    /* Use p2p suffix for any p2p interface. */
    if (strncmp(interface, "p2p",3) == 0) {
        sprintf(daemon_suffix, "p2p");
    } else {
        snprintf(daemon_suffix, MAX_DAEMON_SUFFIX, "%s", interface);
    }
}

/*
 * Start the dhcp client daemon, and wait for it to finish
 * configuring the interface.
 */
int dhcp_do_request(const char *interface,
                    char *ipaddr,
                    char *gateway,
                    uint32_t *prefixLength,
                    char *dns1,
                    char *dns2,
                    char *server,
                    uint32_t  *lease)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.start";
    const char *desired_status = "running";
    char daemon_suffix[MAX_DAEMON_SUFFIX];

    get_daemon_suffix(interface, daemon_suffix);

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            daemon_suffix);

    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");

#ifdef USE_MOTOROLA_CODE
    // BEGIN MOT ICS UPMERGE, w20079, Nov 22, 2011
    // Changed for auto ip feature
    int wait_time = 30;
    char * dhcp_param = "-ABKL";
    int wifiorbt = get_device_type(interface);
    if (wifiorbt < 0) return -1;
    if( autoip_enabled[wifiorbt] ) {
        wait_time = 90;
        dhcp_param = "-BK";
    }
    //END MOT ICS UPMERGE
#endif

    /* Start the daemon and wait until it's ready */
    if (property_get(HOSTNAME_PROP_NAME, prop_value, NULL) && (prop_value[0] != '\0'))
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:-h %s %s", DAEMON_NAME, daemon_suffix,
                 prop_value, interface);
    else
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:%s", DAEMON_NAME, daemon_suffix, interface);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 10) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for dhcpcd to start");
        return -1;
    }

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, 30) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for DHCP to finish");
        return -1;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "DHCP result property was not set");
        return -1;
    }

#ifdef USE_MOTOROLA_CODE
    //BEGIN MOT ICS UPMERGE, w20079, Nov 22, 2011
    //Changed for auto ip feature
    if (strcmp(prop_value, "ok") == 0 || strcmp(prop_value, "limited") == 0) {
    //END MOT ICS UPMERGE
#else
    if (strcmp(prop_value, "ok") == 0) {
#endif
        char dns_prop_name[PROPERTY_KEY_MAX];
        if (fill_ip_info(interface, ipaddr, gateway, prefixLength, dns1, dns2, server, lease)
                == -1) {
            return -1;
        }

        /* copy dns data to system properties - TODO - remove this after we have async
         * notification of renewal's */
        snprintf(dns_prop_name, sizeof(dns_prop_name), "net.%s.dns1", interface);
        property_set(dns_prop_name, *dns1 ? ipaddr_to_string(*dns1) : "");
        snprintf(dns_prop_name, sizeof(dns_prop_name), "net.%s.dns2", interface);
        property_set(dns_prop_name, *dns2 ? ipaddr_to_string(*dns2) : "");
        return 0;
    } else {
        snprintf(errmsg, sizeof(errmsg), "DHCP result was %s", prop_value);
        return -1;
    }
}

/**
 * Stop the DHCP client daemon.
 */
int dhcp_stop(const char *interface)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.stop";
    const char *desired_status = "stopped";

    char daemon_suffix[MAX_DAEMON_SUFFIX];

    get_daemon_suffix(interface, daemon_suffix);

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            daemon_suffix);

    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s", DAEMON_NAME, daemon_suffix);

    /* Stop the daemon and wait until it's reported to be stopped */
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 5) < 0) {
        return -1;
    }
    property_set(result_prop_name, "failed");
    return 0;
}

/**
 * Release the current DHCP client lease.
 */
int dhcp_release_lease(const char *interface)
{
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.stop";
    const char *desired_status = "stopped";

    char daemon_suffix[MAX_DAEMON_SUFFIX];

    get_daemon_suffix(interface, daemon_suffix);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            daemon_suffix);

    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s", DAEMON_NAME, daemon_suffix);

    /* Stop the daemon and wait until it's reported to be stopped */
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 5) < 0) {
        return -1;
    }
    return 0;
}

char *dhcp_get_errmsg() {
    return errmsg;
}

#ifdef USE_MOTOROLA_CODE
// BEGIN MOT ICS UPMERGE, w20079, Nov 22, 2011
int dhcp_get_state(const char *interface,
                    in_addr_t *ipaddr,
                    in_addr_t *gateway,
                    in_addr_t *mask,
                    in_addr_t *dns1,
                    in_addr_t *dns2,
                    in_addr_t *server,
                    uint32_t  *lease) {
    int result=0;
    char result_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = "null";

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            interface);

    // Changed for auto ip feature
    int wifiorbt = get_device_type(interface);
    if( wifiorbt < 0 ) {
        *ipaddr=0;
        *gateway=0;
        *mask=0;
        *dns1=0;
        *dns2=0;
        *server=0;
        return 0;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "dhcp_get_state:DHCP result property was not set");
    }

    if (strcmp(prop_value, "ok") == 0)
        result=1;
    else if (strcmp(prop_value, "limited") == 0)
        result=2;

    if (result) {
        char pv_ipaddr[PROPERTY_VALUE_MAX];
        char pv_gateway[PROPERTY_VALUE_MAX];
        char pv_dns1[PROPERTY_VALUE_MAX];
        char pv_dns2[PROPERTY_VALUE_MAX];
        char pv_server[PROPERTY_VALUE_MAX];
        char prop_name[PROPERTY_KEY_MAX];
        char prop_value[PROPERTY_VALUE_MAX];
        uint32_t prefixLength;
        struct in_addr addr;

        int rv = fill_ip_info(interface, pv_ipaddr, pv_gateway,
                     &prefixLength, pv_dns1, pv_dns2, pv_server, lease);
        if (rv != -1) {
            *ipaddr = *gateway = *server = 0;
            *dns1 = *dns2 = 0;
            if (inet_aton(pv_ipaddr, &addr)) {
                *ipaddr = addr.s_addr;
            }
            if (inet_aton(pv_gateway, &addr)) {
                *gateway = addr.s_addr;
            }
            if (inet_aton(pv_dns1, &addr)) {
                *dns1= addr.s_addr;
            }
            if (inet_aton(pv_dns2, &addr)) {
                *dns2= addr.s_addr;
            }
            if (inet_aton(pv_server, &addr)) {
                *server= addr.s_addr;
            }
        }
        snprintf(prop_name, sizeof(prop_name), "%s.%s.mask", DHCP_PROP_NAME_PREFIX, interface);
        if (property_get(prop_name, prop_value, NULL) && inet_aton(prop_value, &addr)) {
            *mask = addr.s_addr;
        } else {
            *mask = 0;
        }
        return result;
    }

    *ipaddr=0;
    *gateway=0;
    *mask=0;
    *dns1=0;
    *dns2=0;
    *server=0;

    return 0;
}

void set_autoip(const char *interface, int value)
{
    value = value ? 1 : 0;
    int wifiorbt = get_device_type(interface);
    if( wifiorbt >= 0 ) {
        if( autoip_enabled[wifiorbt] != value ) {
            dhcp_stop(interface);
            autoip_enabled[wifiorbt] = value;
        }
    }
}
// END MOT ICS UPMERGE
#endif

/**
 * Run WiMAX dhcp renew service.
 * "wimax_renew" service shoud be included in init.rc.
 */
int dhcp_do_request_renew(const char *interface,
                    in_addr_t *ipaddr,
                    in_addr_t *gateway,
                    uint32_t *prefixLength,
                    in_addr_t *dns1,
                    in_addr_t *dns2,
                    in_addr_t *server,
                    uint32_t  *lease)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.start";

    char daemon_suffix[MAX_DAEMON_SUFFIX];

    get_daemon_suffix(interface, daemon_suffix);

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            interface);

    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");

    /* Start the renew daemon and wait until it's ready */
    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:%s", DAEMON_NAME_RENEW,
            daemon_suffix, interface);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    property_set(ctrl_prop, daemon_cmd);

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, 30) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for DHCP Renew to finish");
        return -1;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "DHCP Renew result property was not set");
        return -1;
    }
    if (strcmp(prop_value, "ok") == 0) {
        fill_ip_info(interface, ipaddr, gateway, prefixLength, dns1, dns2, server, lease);
        return 0;
    } else {
        snprintf(errmsg, sizeof(errmsg), "DHCP Renew result was %s", prop_value);
        return -1;
    }
}
