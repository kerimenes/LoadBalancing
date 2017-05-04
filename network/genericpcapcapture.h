#ifndef GENERICPCAPCAPTURE_H
#define GENERICPCAPCAPTURE_H

#include "pcapreader.h"

#include <QHash>

class NetworkStats;

class StatsInterface
{
public:
	virtual qint64 getTotal() const = 0;
	virtual float getBytesPerSec() const = 0;
};

class GenericPcapCapture : public PcapReader
{
	Q_OBJECT
public:
	explicit GenericPcapCapture(QObject *parent = 0);

	virtual void parsePacket(const uchar *data, pcap_pkthdr *pkthdr);

	const QStringList getIpList();
	const QStringList getSrcIpList();
	const QStringList getDstIpList();
	const QList<quint16> getSrcPortList();
	const QList<quint16> getDstPortList();

	const StatsInterface * getSrcIpStats(const QString &ip);
	const StatsInterface * getDstIpStats(const QString &ip);
	const StatsInterface * getIpStats(const QString &ip);

	const StatsInterface * getDstPortStats(quint16 port);
signals:

public slots:
protected:
	QHash<QString, NetworkStats *> statsBySrcIp;
	QHash<QString, NetworkStats *> statsByDstIp;
	QHash<QString, NetworkStats *> statsByIp;
	QHash<quint16, NetworkStats *> statsByTcpSrcPort;
	QHash<quint16, NetworkStats *> statsByTcpDstPort;
	QHash<quint16, NetworkStats *> statsByUdpSrcPort;
	QHash<quint16, NetworkStats *> statsByUdpDstPort;
	QHash<quint16, NetworkStats *> statsBySrcPort;
	QHash<quint16, NetworkStats *> statsByDstPort;
	QHash<quint16, NetworkStats *> statsByTcpPort;
	QHash<quint16, NetworkStats *> statsByUdpPort;
	QHash<quint16, NetworkStats *> statsByPort;
};

#endif // GENERICPCAPCAPTURE_H
