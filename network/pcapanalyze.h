#ifndef PCAPANALYZE_H
#define PCAPANALYZE_H

#include "genericpcapcapture.h"
#include <QString>

class GenericPcapCapture;

class PcapAnalyze
{
public:
	PcapAnalyze(const QString &targetIface);
	void pcapTest();
	QList<quint16> getDstPortList();
	QHash <quint16, QList<float> > getPortStatus(quint16 port = 0);

	QStringList getDstIPList();
	QStringList getSrcIpList();
	float getDstIPStats(const QString &ip);
	float getSrcIpStats(const QString &ip);
	QHash<QString, float> watchLocalDstIP();
	QHash<QString, float> watchLocalSrcIP();
private:
	GenericPcapCapture *pcap;
	GenericPcapCapture *pcapIp;
	QString iface;
};

#endif // PCAPANALYZE_H
