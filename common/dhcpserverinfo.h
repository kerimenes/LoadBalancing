#ifndef DHCPSERVERINFO_H
#define DHCPSERVERINFO_H

#include <QObject>
#include <QMultiHash>
#include <QStringList>

class DhcpServerInfo : public QObject
{
	Q_OBJECT
public:
	explicit DhcpServerInfo(QObject *parent = 0);

	const QStringList getIPList();
	const QStringList getMACList();
	const QList<QHash<QString, QString> > getInfoByIP(const QString &ip);
	const QList<QHash<QString, QString> > getInfoByMAC(const QString &mac);

	const QStringList getTimeList();
protected:
	int fetchInfo();
	int parseInfo(const QString &resp);

	QMultiHash<QString, QHash<QString, QString> > infoByIp;
	QMultiHash<QString, QHash<QString, QString> > infoByMac;
	QMultiHash<QString, QHash<QString, QString> > infoByTime;
	QString serverIp;

};

#endif // DHCPSERVERINFO_H
