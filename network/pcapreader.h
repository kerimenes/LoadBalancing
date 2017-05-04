#ifndef PCAPREADER_H
#define PCAPREADER_H

#include <QObject>
#include <QFile>
#include <QMap>
#include <QVariant>
#include <QStringList>
#include <QMutex>
#include <QTime>

#ifdef Q_OS_WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

typedef	u_int bpf_u_int32;

class CaptureThread;

struct pcap_pkthdr;

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define SIZE_UDP 8

/* Ethernet header */
struct sniff_ethernet {
		u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
		u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
		u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
		u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
		u_char  ip_tos;                 /* type of service */
		u_short ip_len;                 /* total length */
		u_short ip_id;                  /* identification */
		u_short ip_off;                 /* fragment offset field */
		#define IP_RF 0x8000            /* reserved fragment flag */
		#define IP_DF 0x4000            /* dont fragment flag */
		#define IP_MF 0x2000            /* more fragments flag */
		#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
		u_char  ip_ttl;                 /* time to live */
		u_char  ip_p;                   /* protocol */
		u_short ip_sum;                 /* checksum */
		struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct sniff_udp {
	u_short udp_src;
	u_short udp_dst;
	u_short udp_len;
	u_short udp_crc;
};

struct sniff_tcp {
	u_short udp_src;
	u_short udp_dst;
	u_int seq;
	u_int ack;
	u_int flags;
	u_short chksum;
	u_short urg;
};

class PcapPacket {
public:
	PcapPacket()
	{
		payload = NULL;
		parsed = false;
	}
	~PcapPacket()
	{
		if (payload)
			delete payload;
		payload = NULL;
	}

	struct sniff_ip ip;
	struct sniff_udp udp;
	uchar *payload;
	int payloadLen;
	bool marked;
	bool parsed;
	QTime ts;
};

class PcapReader : public QObject
{
	Q_OBJECT
public:
	enum settings {
		DETECT_RTP_DUP,
		DETECT_H264_SEI_MSG,
		DETECT_RTP_FUA_START,
		DO_NOT_KEEP_PACKETS
	};

	explicit PcapReader(QObject *parent = 0);
	virtual void read(QString filename);
	virtual void parsePacket(const uchar *data, pcap_pkthdr *pkthdr);
	int getPacketCount() { return packets.size(); }
	PcapPacket * getPacket(int no) { return packets[no]; }
	virtual QString getHtmlData(int) { return ""; }
	virtual QString getXmlData(int) { return ""; }
	virtual QString getRtpInfo(int) { return ""; }
	QString getSrcIpAddress(int packet);
	QString getDstIpAddress(int packet);
	int getSrcPort(int packet);
	int getDstPort(int packet);
	virtual void setSetting(settings setting, QVariant value);
	QStringList getCaptureLog();

	virtual int capture(QString iface = "", QString filter = "");
	virtual int stopCapture();
	int setCaptureFilter(QString filter);
	QVariant getCaptureStat(QString statName);

	QVariant getAnalysisData(QString key);

protected:
	virtual void parseTcpData(const uchar *, uint) {}
	virtual void parseUdpData(const uchar *, uint) {}

	int packetCount;
	QList<PcapPacket *> packets;
	QMap<settings, QVariant> capSettings;
	QMap<QString, QVariant> analysisData;
	QStringList capLog;
	CaptureThread *cThread;
	QMutex capLock;
	QString captureInterface;
	bpf_u_int32 net;
	quint64 bytesPerSec;
	timeval referenceTs;
};

#endif // PCAPREADER_H
