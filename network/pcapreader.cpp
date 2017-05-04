#include "pcapreader.h"

#include <pcap.h>

#include <QDebug>
#include <QHostAddress>
#include <QThread>

#include <sys/time.h>

class CaptureThread : public QThread
{
public:
	CaptureThread(pcap_t *cap, PcapReader *reader)
	{
		pcap = cap;
		parent = reader;
	}
	void run()
	{
		pcap_pkthdr header;
		exit = false;
		lock.lock();
		while (!exit) {
			const u_char *data = pcap_next(pcap, &header);
			if (exit)
				break;
			if (data)
				parent->parsePacket(data, &header);
		}
		lock.unlock();
	}

	void close()
	{
		exit = true;
		lock.lock();
		lock.unlock();
	}

	pcap_t *pcap;
	bool exit;
	PcapReader *parent;
	QMutex lock;
};

PcapReader::PcapReader(QObject *parent) :
	QObject(parent)
{
	cThread = NULL;
}

void PcapReader::read(QString filename)
{
	qDeleteAll(packets);
	packets.clear();
	packetCount = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *cap = pcap_open_offline(qPrintable(filename), errbuf);
	if (!cap) {
		qDebug() << "cannot open pcap file:" << errbuf;
		return;
	}
	pcap_pkthdr header;
	const u_char *data = pcap_next(cap, &header);
	while (data) {
		data = pcap_next(cap, &header);
		if (data)
			parsePacket(data, &header);
	}
	pcap_close(cap);
}

static long long timeval_subtract(struct timeval *x, struct timeval *y)
{
	struct timeval result;
	//struct timeval *result, *x, *y;
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
		  tv_usec is certainly positive. */
	result.tv_sec = x->tv_sec - y->tv_sec;
	result.tv_usec = x->tv_usec - y->tv_usec;

	return result.tv_sec * 1000000ull + result.tv_usec;

	/* Return 1 if result is negative. */
	//return x->tv_sec < y->tv_sec;
}

void PcapReader::parsePacket(const uchar *data, pcap_pkthdr *pkthdr)
{
	sniff_ethernet *ethernet = (sniff_ethernet *)data;
	ethernet->ether_type = ntohs(ethernet->ether_type);
	sniff_ip *ip = NULL;
	uint etherSize = SIZE_ETHERNET;
	if (ethernet->ether_type == 0x8100 && (data[SIZE_ETHERNET + 2] *256 + data[SIZE_ETHERNET + 3]) == 0x800)  { //tagged virtual lan
		ip = (sniff_ip *)(data + SIZE_ETHERNET + 4);
		etherSize = SIZE_ETHERNET + 4;
	} else if (ethernet->ether_type == 0x800) //ip
		ip = (sniff_ip *)(data + SIZE_ETHERNET);
	else
		return;
	int sizeIp = IP_HL(ip) * 4;
	capLock.lock();
	if (packetCount == 0) {
		referenceTs = pkthdr->ts;
		bytesPerSec = 0;
	}
	packetCount++;
	packets << new PcapPacket;
	qint32 tdiff = timeval_subtract(&pkthdr->ts, &referenceTs) / 1000ll;
	bytesPerSec += pkthdr->caplen;
	if (tdiff > 1000) {
		capLog << QString("tdiff %1").arg(tdiff);
		analysisData.insert("bandwidth", bytesPerSec * 1000 / tdiff / 1024);
		bytesPerSec = 0;
		referenceTs = pkthdr->ts;
	}
	packets.last()->ts.addMSecs(tdiff);
	packets.last()->marked = false;
	packets.last()->ip = *ip;
	packets.last()->payloadLen = 0;
	if (sizeIp < 20) {
		delete packets.takeLast();
		qDebug() << sizeIp << "hmm" <<pkthdr->caplen << pkthdr->len << getSrcIpAddress(packets.size() - 1) << ethernet->ether_type << 0x8100;
		capLock.unlock();
		return;
	}
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		parseTcpData(data + etherSize + sizeIp, pkthdr->len - etherSize - sizeIp);
		break;
	case IPPROTO_UDP:
		parseUdpData(data + etherSize + sizeIp, pkthdr->len - etherSize - sizeIp);
		break;
	case IPPROTO_ICMP:
		break;
	case IPPROTO_IP:
		break;
	default:
		break;
	}
	if (capSettings[DO_NOT_KEEP_PACKETS].toBool()) {
		PcapPacket *pack = packets.takeLast();
		delete pack;
	}
	capLock.unlock();
}

QString PcapReader::getSrcIpAddress(int packet)
{
	QHostAddress addr(ntohl(packets[packet]->ip.ip_src.s_addr));
	return addr.toString();
}

QString PcapReader::getDstIpAddress(int packet)
{
	QHostAddress addr(ntohl(packets[packet]->ip.ip_dst.s_addr));
	return addr.toString();
}

int PcapReader::getSrcPort(int packet)
{
	return ntohs(packets[packet]->udp.udp_src);
}

int PcapReader::getDstPort(int packet)
{
	return ntohs(packets[packet]->udp.udp_dst);
}

void PcapReader::setSetting(settings setting, QVariant value)
{
	capSettings.insert(setting, value);
}

QStringList PcapReader::getCaptureLog()
{
	QStringList log;
	capLock.lock();
	log = capLog;
	capLog.clear();
	capLock.unlock();
	return log;
}

int PcapReader::capture(QString iface, QString filter)
{
	if (iface.isEmpty())
		iface = captureInterface;
	qDeleteAll(packets);
	packets.clear();
	packetCount = 0;
	struct bpf_program bpf;
	bpf_u_int32 mask;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_lookupnet(qPrintable(iface), &net, &mask, errbuf)) {
		qDebug() << "error looking up device netmask:" << errbuf;
		return -1;
	}
	pcap_t *cap = pcap_open_live(qPrintable(iface), BUFSIZ, 1, 1000, errbuf);
	if (cap == NULL) {
		qDebug() << "cannot open pcap file:" << errbuf;
		return -2;
	}
	if (filter.size() && pcap_compile(cap, &bpf, qPrintable(filter), 0, net) < 0) {
		qDebug() << "error while compiling pcap filter" << filter << ":" << pcap_geterr(cap);
		return -3;
	}
	if (filter.size() && pcap_setfilter(cap, &bpf)) {
		qDebug() << "error while setting pcap filter:" << pcap_geterr(cap);
		return -4;
	}
	cThread = new CaptureThread(cap, this);
	cThread->start(QThread::LowPriority);
	return 0;
}

int PcapReader::stopCapture()
{
	if (cThread) {
		cThread->close();
		pcap_close(cThread->pcap);
		delete cThread;
		cThread = NULL;
	}
	return 0;
}

int PcapReader::setCaptureFilter(QString filter)
{
	struct bpf_program bpf;
	if (pcap_compile(cThread->pcap, &bpf, qPrintable(filter), 0, net) < 0) {
		qDebug() << "error while compiling pcap filter" << filter << ":" << pcap_geterr(cThread->pcap);
		return -1;
	}
	if (pcap_setfilter(cThread->pcap, &bpf)) {
		qDebug() << "error while setting pcap filter:" << pcap_geterr(cThread->pcap);
		return -1;
	}
	capLock.lock();
	qDeleteAll(packets);
	packets.clear();
	packetCount = 0;
	capLock.unlock();
	return 0;
}

QVariant PcapReader::getCaptureStat(QString statName)
{
	if (!cThread->pcap)
		return QVariant();
	pcap_stat stat;
	pcap_stats(cThread->pcap, &stat);
	//stat.
	return QVariant();
}

QVariant PcapReader::getAnalysisData(QString key)
{
	capLock.lock();
	QVariant var = analysisData[key];
	capLock.unlock();
	return var;
}
