#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <PCSC/ifdhandler.h>

#define SELECT_READER    0x01
#define CREATE_CHANNEL   0x02
#define CLOSE_CHANNEL    0x03
#define ICC_PRESENCE     0x04
#define POWER_ICC        0x05
#define GET_ATR          0x06
#define TRANSMIT_TO_ICC  0x07
#define CONTROL          0x08
#define SET_PROTO_PARAM  0x09

#define IFD_GENERAL_ERROR 620

#define PACKET_HDR_SIZE     4

#define goto_out(a) { if (status == IFD_SUCCESS) status = a; goto out; }

static void close_socket(void);

typedef uint32_t DWORD32;

static int s = -1;
static char config_file[FILENAME_MAX];
static bool first_time = true;
static bool enabled = true;
static bool debug = false;

static void dbgprintf(char *format, ...) {
    va_list args;
    va_start(args, format);
    if (debug)
        vfprintf(stderr, format, args);
    va_end(args);
}

static void dump(char *hdr, PUCHAR data, WORD len) {
    dbgprintf("%s", hdr);
    while (len-- > 0)
        dbgprintf(" %02X", *data++);
}

static void compose_packet(PUCHAR buffer, uint16_t cmd, uint16_t len, void *data, uint16_t data_len)
{
    buffer[0] = cmd / 256;
    buffer[1] = cmd % 256;
    buffer[2] = len / 256;
    buffer[3] = len % 256;
    if (data_len != 0)
        memcpy(&buffer[4], data, data_len);
}

static RESPONSECODE send_and_receive(PUCHAR txbuffer, WORD txlength, PUCHAR rxbuffer, PDWORD rxlength) {

    RESPONSECODE status = IFD_SUCCESS;
    uint16_t len, tmp;

    dump(">", txbuffer, txlength);
    dbgprintf("\n");

    if (send(s, txbuffer, txlength, 0) != txlength)
        goto_out(IFD_COMMUNICATION_ERROR);

    dbgprintf("<");

    if (recv(s, &tmp, sizeof(tmp), 0) != sizeof(tmp))
        goto_out(IFD_COMMUNICATION_ERROR);
    status = ntohs(tmp);

    dbgprintf(" %02X %02X", status/256, status % 256);

    if (recv(s, &len, sizeof(len), 0) != sizeof(len))
        goto_out(IFD_COMMUNICATION_ERROR);
    len = ntohs(len);

    dbgprintf(" %02X %02X", len/256, len % 256);

    if (len != 0) {

        if (((rxlength != NULL) && (len > *rxlength)) || (rxlength == NULL) || (rxbuffer == NULL))
            goto_out(IFD_ERROR_INSUFFICIENT_BUFFER);

        *rxlength = len;

        if (recv(s, rxbuffer, len, 0) != len)
            goto_out(IFD_COMMUNICATION_ERROR);

        dump("", rxbuffer, *rxlength);

    }
    dbgprintf("\n");

out:

    if (status == IFD_COMMUNICATION_ERROR)
        close_socket();

    return status;

}


static RESPONSECODE parse_config(char *file, struct sockaddr_in *addr, char *reader)
{

    RESPONSECODE status = IFD_SUCCESS;
    FILE *fh;

    addr->sin_family = AF_INET;
    addr->sin_port = 0;
    memset(reader, 0, MAX_READERNAME);

    fh = fopen(file, "r");
    if (fh == NULL)
        goto_out(IFD_GENERAL_ERROR);
    while (!feof(fh)) {
        char *kw, line[128] = { 0 }, *ptr = line + 1;
        if (fgets(line, sizeof(line), fh) == NULL)
            break;
        if (line[0] != '#')
            continue;
        while (iscntrl(ptr[strlen(ptr) - 1]))
            ptr[strlen(ptr) - 1] = 0;
        kw = "ENABLED";
        if (strncmp(ptr, kw, strlen(kw)) == 0) {
            ptr += strlen(kw);
            while (*ptr == ' ')
                ptr++;
            enabled = atoi(ptr) != 0;
            dbgprintf("%s: %d\n", kw, enabled);
        }
        kw = "READER";
        if (strncmp(ptr, kw, strlen(kw)) == 0) {
            ptr += strlen(kw);
            while (*ptr == ' ')
                ptr++;
            strncpy(reader, ptr, MAX_READERNAME - 1);
            dbgprintf("%s: %s\n", kw, reader);
        }
        kw = "SERVER";
        if (strncmp(ptr, kw, strlen(kw)) == 0) {
            ptr += strlen(kw);
            while (*ptr == ' ')
                ptr++;
            if (strchr(ptr, ':') == 0)
                continue;
            *strchr(ptr, ':') = 0;
            addr->sin_addr.s_addr = inet_addr(ptr);
            ptr += strlen(ptr);
            addr->sin_port = ntohs(atoi(++ptr));
            dbgprintf("%s: %s:%d\n", kw, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
        }
        kw = "DEBUG";
        if (strncmp(ptr, kw, strlen(kw)) == 0) {
            ptr += strlen(kw);
            while (*ptr == ' ')
                ptr++;
            debug = atoi(ptr) != 0;
            dbgprintf("%s: %d\n", kw, debug);
        }
    }
    fclose(fh);

    if ((reader[0] == 0) || (addr->sin_port == 0))
        status = IFD_GENERAL_ERROR;

out:

    return status;

}

static void close_socket(void) {

    if (s != -1)
        close(s);
    s = -1;

}

static RESPONSECODE open_socket() {

    RESPONSECODE status = IFD_SUCCESS;
    struct sockaddr_in server;
    char reader[MAX_READERNAME];
    UCHAR packet[PACKET_HDR_SIZE + sizeof(reader)];

    if (s != -1)
        goto_out(IFD_SUCCESS);

    if (parse_config(config_file, &server, reader) != IFD_SUCCESS)
        goto_out(IFD_GENERAL_ERROR);

    if (!enabled)
        goto_out(IFD_SUCCESS);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1)
        goto_out(IFD_COMMUNICATION_ERROR);

    if (connect(s, (struct sockaddr*)&server, sizeof(server)) == -1) {
        close_socket();
        goto_out(IFD_COMMUNICATION_ERROR);
    }

    first_time = false;

    compose_packet(packet, SELECT_READER, strlen(reader), reader, strlen(reader));
    status = send_and_receive(packet, PACKET_HDR_SIZE + strlen(reader), NULL, 0);

out:

    return status;

}


RESPONSECODE IFDHControl(DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer, DWORD RxLength, LPDWORD pdwBytesReturned) {

    RESPONSECODE status = IFD_SUCCESS;
    DWORD32 ctrl_code;
    PUCHAR packet = NULL;
    WORD plen;
    DWORD len;

    dbgprintf("IFDHControl Lun=%lu dwControlCode=%lu TxBuffer=%p TxLength=%lu RxBuffer=%p RxLength=%lu pdwBytesReturned=%p\n", Lun, dwControlCode, TxBuffer, TxLength, RxBuffer, RxLength, pdwBytesReturned);

    if ((status = open_socket()) != IFD_SUCCESS)
        goto_out(status);

    if (TxLength > 65531)
        goto_out(IFD_ERROR_INSUFFICIENT_BUFFER);

    plen = sizeof(ctrl_code) + TxLength;

    packet = malloc(65535);
    if (packet == NULL)
        goto_out(IFD_ERROR_INSUFFICIENT_BUFFER);

    ctrl_code = htonl(dwControlCode);
    compose_packet(packet, CONTROL, plen, &ctrl_code, sizeof(ctrl_code));
    memcpy(&packet[PACKET_HDR_SIZE + sizeof(ctrl_code)], TxBuffer, TxLength);
    len = 65535;
    status = send_and_receive(packet, PACKET_HDR_SIZE + plen, packet, &len);
    if (status != IFD_SUCCESS)
        goto_out(status);
    if ((RxLength < len) || (RxBuffer == NULL))
        goto_out(IFD_ERROR_INSUFFICIENT_BUFFER);

    *pdwBytesReturned = len;
    memcpy(RxBuffer, packet, len);

out:

    if (packet != NULL)
        free(packet);

    return status;

}

RESPONSECODE IFDHCreateChannelByName(DWORD Lun, LPSTR DeviceName) {

    RESPONSECODE status = IFD_SUCCESS;
    UCHAR packet[PACKET_HDR_SIZE];

    dbgprintf("IFDHCreateChannelByName Lun=%lu DeviceName=%s\n", Lun, DeviceName);

    strncpy(config_file, DeviceName, sizeof(config_file));

    if ((status = open_socket()) != IFD_SUCCESS) {
        goto_out(status);
    }

    if (!enabled)
        return IFD_SUCCESS;

    compose_packet(packet, CREATE_CHANNEL, 0, NULL, 0);
    status = send_and_receive(packet, sizeof(packet), NULL, 0);

out:

    if (first_time && (status == IFD_COMMUNICATION_ERROR)) {
//      dbgprintf("IFDHCreateChannelByName NOT REACH\n");
        status = IFD_SUCCESS;
    }

    return status;

}

RESPONSECODE IFDHCreateChannel(DWORD Lun, DWORD Channel) {

    dbgprintf("IFDHCreateChannelByName Lun=%lu Channel=%lu\n", Lun, Channel);

    return IFD_NOT_SUPPORTED;

}

RESPONSECODE IFDHCloseChannel(DWORD Lun) {

    RESPONSECODE status = IFD_SUCCESS;
    UCHAR packet[PACKET_HDR_SIZE];

    dbgprintf("IFDHCloseChannel Lun=%lu\n", Lun);

    if ((status = open_socket()) != IFD_SUCCESS)
        goto_out(status);

    if (!enabled)
        return IFD_SUCCESS;

    compose_packet(packet, CLOSE_CHANNEL, 0, NULL, 0);
    status = send_and_receive(packet, sizeof(packet), NULL, 0);

out:

    close_socket();

    return status;

}

RESPONSECODE IFDHGetCapabilities(DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value) {

    RESPONSECODE status = IFD_SUCCESS;
    UCHAR packet[PACKET_HDR_SIZE];

    dbgprintf("IFDHGetCapabilities Lun=%lu Tag=%lu Length=%p, Value=%p\n", Lun, Tag, Length, Value);

    switch (Tag) {
        case TAG_IFD_ATR:
            if ((status = open_socket()) != IFD_SUCCESS)
                goto_out(status);
            compose_packet(packet, GET_ATR, 0, NULL, 0);
            status = send_and_receive(packet, sizeof(packet), Value, Length);
            break;
        case TAG_IFD_SIMULTANEOUS_ACCESS:
            if ((Value == NULL) || (Length == NULL) || (*Length < 1))
                goto_out(IFD_ERROR_INSUFFICIENT_BUFFER)
            Value[0] = 1;
            break;
        case TAG_IFD_SLOTS_NUMBER:
            if ((Value == NULL) || (Length == NULL) || (*Length < 1))
                goto_out(IFD_ERROR_INSUFFICIENT_BUFFER)
            Value[0] = 1;
            break;
        case TAG_IFD_SLOT_THREAD_SAFE:
            if ((Value == NULL) || (Length == NULL) || (*Length < 1))
                goto_out(IFD_ERROR_INSUFFICIENT_BUFFER)
            Value[0] = 0;
            break;
        case TAG_IFD_POLLING_THREAD_WITH_TIMEOUT:
            if ((Value == NULL) || (Length == NULL) || (*Length < 1))
                goto_out(IFD_ERROR_INSUFFICIENT_BUFFER)
            Value[0] = 0;
            break;
        default:
            goto_out(IFD_ERROR_TAG);
    }

out:

    return status;

}

RESPONSECODE IFDHSetCapabilities(DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value) {

    dbgprintf("IFDHSetCapabilities Lun=%lu Tag=%lu Length=%lu, Value=%p\n", Lun, Tag, Length, Value);

    return IFD_NOT_SUPPORTED;

}

RESPONSECODE IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol, UCHAR Flags, UCHAR PTS1, UCHAR PTS2, UCHAR PTS3) {

    DWORD32 protocol;
    RESPONSECODE status = IFD_SUCCESS;

    dbgprintf("IFDHSetProtocolParameters Lun=%lu Protocol=%lu Flags=%u, PTS1=%u PTS2=%u PTS3=%u\n", Lun, Protocol, Flags, PTS1, PTS2, PTS3);

    UCHAR packet[PACKET_HDR_SIZE + sizeof(protocol) + 3];

    if ((status = open_socket()) != IFD_SUCCESS)
        goto_out(status);

    protocol = htonl(Protocol);
    compose_packet(packet, SET_PROTO_PARAM, sizeof(protocol) + 3, &protocol, sizeof(protocol));
    packet[PACKET_HDR_SIZE + sizeof(protocol) + 0] = PTS1;
    packet[PACKET_HDR_SIZE + sizeof(protocol) + 1] = PTS2;
    packet[PACKET_HDR_SIZE + sizeof(protocol) + 2] = PTS3;
    status = send_and_receive(packet, sizeof(packet), NULL, 0);

out:

    return status;

}

RESPONSECODE IFDHPowerICC(DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength) {

    RESPONSECODE status = IFD_SUCCESS;
    DWORD32 action32;
    UCHAR packet[PACKET_HDR_SIZE + sizeof(action32)];

    dbgprintf("IFDHPowerICC Lun=%lu Action=%lu Atr=%p, AtrLength=%p\n", Lun, Action, Atr, AtrLength);

    if ((status = open_socket()) != IFD_SUCCESS)
        goto_out(status);

    action32 = htonl(Action);
    compose_packet(packet, POWER_ICC, sizeof(action32), &action32, sizeof(action32));
    status = send_and_receive(packet, sizeof(packet), Atr, AtrLength);

out:

    return status;

}

RESPONSECODE IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer, PDWORD RxLength, PSCARD_IO_HEADER RecvPci) {

    RESPONSECODE status = IFD_SUCCESS;
    DWORD32 protocol32;
    PUCHAR packet = NULL;
    WORD plen;
    DWORD len;

    dbgprintf("IFDHTransmitToICC Lun=%lu SendPci.Protocol=%lu SendPci.Length=%lu TxBuffer=%p TxLength=%lu RxBuffer=%p RxLength=%p RecvPci=%p\n", Lun, SendPci.Protocol, SendPci.Length, TxBuffer, TxLength, RxBuffer, RxLength, RecvPci);

    if ((status = open_socket()) != IFD_SUCCESS)
        goto_out(status);

    if (TxLength > 65531)
        goto_out(IFD_ERROR_INSUFFICIENT_BUFFER);

    plen = sizeof(protocol32) + TxLength;

    packet = malloc(65535);
    if (packet == NULL)
        goto_out(IFD_ERROR_INSUFFICIENT_BUFFER);

    protocol32 = htonl(SendPci.Protocol);
    compose_packet(packet, TRANSMIT_TO_ICC, plen, &protocol32, sizeof(protocol32));
    memcpy(&packet[PACKET_HDR_SIZE + sizeof(protocol32)], TxBuffer, TxLength);
    len = 65535;
    status = send_and_receive(packet, PACKET_HDR_SIZE + plen, packet, &len);
    if (status != IFD_SUCCESS)
        goto_out(status);
    if ((len < sizeof(protocol32)) || (RecvPci == NULL) || (RxLength == NULL) || (RxBuffer == NULL) || (len - sizeof(protocol32) > *RxLength))
        goto_out(IFD_ERROR_INSUFFICIENT_BUFFER);

    RecvPci->Protocol = ntohl(*((DWORD32*)&packet[0]));
    RecvPci->Length = 0;
    memcpy(RxBuffer, &packet[sizeof(protocol32)], len - sizeof(protocol32));
    *RxLength = len - sizeof(protocol32);

out:

    if (packet != NULL)
        free(packet);

    return status;

}

RESPONSECODE IFDHICCPresence(DWORD Lun) {

    RESPONSECODE status = IFD_SUCCESS;
    UCHAR packet[PACKET_HDR_SIZE];
    DWORD rxlen;

    dbgprintf("IFDHICCPresence Lun=%lu\n", Lun);

    if ((status = open_socket()) != IFD_SUCCESS)
        goto_out(status);

    if (!enabled)
        goto_out(IFD_ICC_NOT_PRESENT);

    compose_packet(packet, ICC_PRESENCE, 0, NULL, 0);
    rxlen = 1;
    status = send_and_receive(packet, sizeof(packet), packet, &rxlen);
    if (status != IFD_SUCCESS)
        goto_out(status);
    if (rxlen != 1)
        goto_out(IFD_COMMUNICATION_ERROR);

    status = packet[0] == 1 ? IFD_SUCCESS : IFD_ICC_NOT_PRESENT;

out:

    if (first_time && (status == IFD_COMMUNICATION_ERROR))
        status = IFD_ICC_NOT_PRESENT;

    return status;

}
