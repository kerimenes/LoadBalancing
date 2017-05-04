#include "genericpcapcapture.h"

#include <pcap.h>
#include <sys/time.h>

#include <QDebug>
#include <QMutexLocker>
#include <QHostAddress>

static long long timeval_subtract(struct timeval *x, struct timeval *y)
{
	struct timeval result;
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
}

class NetworkStats : public StatsInterface
{
public:
	NetworkStats()
	{
		totalBytes = 0;
	}

	void newPacket(pcap_pkthdr *pkt)
	{
		if (totalBytes == 0) {
			referenceTs = pkt->ts;
			bytesPerSec = 0;
		}
		totalBytes += pkt->caplen;

		qint32 tdiff = timeval_subtract(&pkt->ts, &referenceTs) / 1000ll;
		bytesPerSec += pkt->caplen;
		if (tdiff > 1000) {
			bps = bytesPerSec * 1000.0 / tdiff;
			bytesPerSec = 0;
			referenceTs = pkt->ts;
		}
	}

	qint64 getTotal() const { return totalBytes; }
	float getBytesPerSec() const { return bps; }

protected:
	quint64 totalBytes;
	qint32 bytesPerSec;
	timeval referenceTs;
	float bps;
};

template <typename T>
static inline void addStat(QHash<T, NetworkStats *> &hash, T key, pcap_pkthdr *pkt)
{
	if (!hash.contains(key))
		hash.insert(key, new NetworkStats());
	hash[key]->newPacket(pkt);
}

GenericPcapCapture::GenericPcapCapture(QObject *parent)
	: PcapReader(parent)
{

}

void GenericPcapCapture::parsePacket(const uchar *data, pcap_pkthdr *pkthdr)
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

	QHostAddress srcIp(ntohl(ip->ip_src.s_addr));
	QHostAddress dstIp(ntohl(ip->ip_dst.s_addr));
	int srcPort = 0, dstPort = 0;

	const uchar *pdata = data + etherSize + sizeIp;
	sniff_tcp *tcp = (sniff_tcp *)pdata;
	sniff_udp *udp = (sniff_udp *)pdata;

#if 1
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		srcPort = ntohs(tcp->udp_src);
		dstPort = ntohs(tcp->udp_dst);

		addStat<quint16>(statsByTcpSrcPort, srcPort, pkthdr);
		addStat<quint16>(statsByTcpDstPort, dstPort, pkthdr);

		addStat<quint16>(statsByTcpPort, srcPort, pkthdr);
		addStat<quint16>(statsByTcpPort, dstPort, pkthdr);
		break;
	case IPPROTO_UDP:
		udp->udp_len = ntohs(udp->udp_len);
		srcPort = ntohs(udp->udp_src);
		dstPort = ntohs(udp->udp_dst);

		addStat<quint16>(statsByUdpSrcPort, srcPort, pkthdr);
		addStat<quint16>(statsByUdpDstPort, dstPort, pkthdr);
		addStat<quint16>(statsByUdpPort, srcPort, pkthdr);
		addStat<quint16>(statsByUdpPort, dstPort, pkthdr);
		break;
	case IPPROTO_ICMP:
		break;
	case IPPROTO_IP:
		break;
	default:
		break;
	}
#endif
	addStat<QString>(statsBySrcIp, srcIp.toString(), pkthdr);
	addStat<QString>(statsByDstIp, dstIp.toString(), pkthdr);
	addStat<QString>(statsByIp, srcIp.toString(), pkthdr);
	addStat<QString>(statsByIp, dstIp.toString(), pkthdr);

	if (srcPort && dstPort) {
		addStat<quint16>(statsBySrcPort, srcPort, pkthdr);
		addStat<quint16>(statsByDstPort, dstPort, pkthdr);
		addStat<quint16>(statsByPort, srcPort, pkthdr);
		addStat<quint16>(statsByPort, dstPort, pkthdr);
	}

	capLock.unlock();
}

const QStringList GenericPcapCapture::getIpList()
{
	QMutexLocker l(&capLock);
	return statsByIp.keys();
}

const QStringList GenericPcapCapture::getSrcIpList()
{
	QMutexLocker l(&capLock);
	return statsBySrcIp.keys();
}

const QStringList GenericPcapCapture::getDstIpList()
{
	QMutexLocker l(&capLock);
	return statsByDstIp.keys();
}

const QList<quint16> GenericPcapCapture::getSrcPortList()
{
	QMutexLocker l(&capLock);
	return statsBySrcPort.keys();
}

const QList<quint16> GenericPcapCapture::getDstPortList()
{
	QMutexLocker l(&capLock);
	return statsByDstPort.keys();
}

const StatsInterface *GenericPcapCapture::getSrcIpStats(const QString &ip)
{
	QMutexLocker l(&capLock);
	if (!statsBySrcIp.contains(ip))
		return NULL;
	return statsBySrcIp[ip];
}

const StatsInterface *GenericPcapCapture::getDstIpStats(const QString &ip)
{
	QMutexLocker l(&capLock);
	if (!statsByDstIp.contains(ip))
		return NULL;
	return statsByDstIp[ip];
}

const StatsInterface *GenericPcapCapture::getDstPortStats(quint16 port)
{
//		qDebug() << "StatsInterface GetDstPortStats";
		QMutexLocker l(&capLock);
		if (!statsByDstPort.contains(port))
			return NULL;
		return statsByDstPort[port];
}

const StatsInterface *GenericPcapCapture::getIpStats(const QString &ip)
{
	QMutexLocker l(&capLock);
	if (!statsByIp.contains(ip))
		return NULL;
	return statsByIp[ip];
}

