#ifndef LOADBALANCING_H
#define LOADBALANCING_H

#include <QTimer>
#include <QObject>

#include "common/tcpserver.h"
#include "common/dhcpserverinfo.h"

#include "network/pcapanalyze.h"

class LoadBalancing : QObject
{
	Q_OBJECT
public:
	LoadBalancing(QObject * parent = 0);
	void splitIP(void);
	void networkStateInfo();
	QStringList splitISP();
	QStringList checkISPState();
	void checkIPruleList(const QString &ip);
	void checkIPstatus(const QString &ip);
	void init();
	void checkMacAdress(QHash<QString, QString> lease);
protected slots:
	void timeout();
	void gettingData(QByteArray data);
protected:
	int addRule(const QString &ip, const QString &table);
	int deleteRule(const QString &ip, const QString &table);
	void addRoute(const QString &iface, const QString &ip, const QString &table);
	void deleteRoute(const QString &iface, const QString &ip, const QString &table);
private:
	DhcpServerInfo *dserver;
	PcapAnalyze *analyze;
	TcpServer *tcp;
	QStringList iplist;
	QString vlanno;
	QString personalgrp;
	QTimer *timer;
	QHash <QString, float> ifacedownload;
	QString ip;
	QString mac;

};

#endif // LOADBALANCING_H
