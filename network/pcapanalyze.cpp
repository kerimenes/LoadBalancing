#include "pcapanalyze.h"

#include "genericpcapcapture.h"

#include <QDebug>

PcapAnalyze::PcapAnalyze(const QString &targetIface)
{
	iface = targetIface;
	pcap = NULL;
	pcap = new GenericPcapCapture();
	int err = pcap->capture(iface);

	//	pcapIp = NULL;
	//	pcapIp = new GenericPcapCapture();
	//	int err = pcapIp->capture(iface);
	if (err)
		qDebug() << "pcap error " << err;
	else qDebug() << "not error " << err;
}

void PcapAnalyze::pcapTest()
{
	qDebug() << pcap->getDstPortList();
	if (pcap) {
		const StatsInterface *sif = pcap->getDstPortStats(pcap->getDstPortList().at(0));
		if (sif);
	}
}


QList <quint16> PcapAnalyze::getDstPortList()
{
	if (pcap)
		return pcap->getDstPortList();
	return QList<quint16>();
}

QHash <quint16, QList<float> > PcapAnalyze::getPortStatus(quint16 port)
{
	QHash <quint16, QList<float> > pstats;
	if (pcap) {
		if(port == 0) {
			foreach (quint16 p, getDstPortList()) {
				const StatsInterface *sif = pcap->getDstPortStats(p);
				pstats.insert(p, QList<float>() << sif->getBytesPerSec());
			}
		} else {
			const StatsInterface *sif = pcap->getDstPortStats(port);
			if (sif != 0) {
				pstats.insert(port, QList<float>() << (float )sif->getTotal() * 8 / 1024 / 1024);
			}
		}
		return pstats;
	} else
		return QHash <quint16, QList<float> >();
}

QStringList PcapAnalyze::getDstIPList()
{
	if(pcap) {
		QStringList dstIPList = pcap->getDstIpList();
		QStringList localDstIpList;
		foreach (const QString &ip, dstIPList) {
			if (ip.startsWith("10.") | (ip.startsWith("192.") & ip.contains(".168.")))
				localDstIpList << ip;
		}
		return localDstIpList;
	}
	return QStringList("");
}

QStringList PcapAnalyze::getSrcIpList()
{
	if(pcap){
		QStringList srcIPList = pcap->getSrcIpList();
		QStringList localSrcIpList;
		foreach (const QString &ip, srcIPList) {
			if (ip.startsWith("10.") | (ip.startsWith("192.") & ip.contains(".168.")))
				localSrcIpList << ip;
		}
		return localSrcIpList;
	}	return QStringList("");
}

float PcapAnalyze::getDstIPStats(const QString &ip)
{
	if(pcap) {
		const StatsInterface *sif = pcap->getDstIpStats(ip);
		if(sif)
			return (float )sif->getTotal() * 8 / 1024 / 1024;
	}
	return 0;
}

float PcapAnalyze::getSrcIpStats(const QString &ip)
{
	if(pcap) {
		const StatsInterface *sif = pcap->getSrcIpStats(ip);
		if (sif)
			return (float )sif->getTotal() * 8 / 1024 / 1024;
	}
	return 0;
}

QHash <QString, float> PcapAnalyze::watchLocalDstIP()
{
	QHash <QString, float> ipstats;
	QStringList localDstIpList = getDstIPList();
	if (!localDstIpList.isEmpty()) {
		foreach (const QString &ip, localDstIpList) {
			ipstats.insert(ip, getDstIPStats(ip));
		}
		return ipstats;
	}
	else return QHash<QString, float> ();
}

QHash <QString, float> PcapAnalyze::watchLocalSrcIP()
{
	QHash <QString, float> ipstats;
	QStringList localSrcIpList = getDstIPList();
	if(!localSrcIpList.isEmpty()) {
		foreach (const QString &ip, localSrcIpList) {
			ipstats.insert(ip, getDstIPStats(ip));
		}
		return ipstats;
	}
	else return QHash<QString, float> ();
}
