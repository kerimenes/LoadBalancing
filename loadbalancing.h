#ifndef LOADBALANCING_H
#define LOADBALANCING_H

#include <QTimer>
#include <QObject>
#include <QProcess>

#include "common/tcpserver.h"
#include "common/dhcpserverinfo.h"

#include "ecl/settings/applicationsettings.h"


#include "network/pcapanalyze.h"

class LoadBalancing : QObject
{
	Q_OBJECT
public:
	LoadBalancing(QObject * parent = 0);
	void splitIP(void);
	QHash<QString, float> networkStateInfo();
	void checkIPruleList(const QString &ip, const QString &table);
	void checkIPstatus(const QString &ip);
	void init();
	void checkMacAdress(QHash<QString, QString> lease);
	void logFile(const QString &logdata);
	void gettingNetworkData();
	QString checkMACfile(const QString &macpath, QHash<QString, QString> lease, QString type);
	int iptablesRun(const QStringList &cmd);
	int processRun(const QString &cmd);
protected slots:
	void timeout();
	void gettingData(QByteArray data);
	void processOutput();
protected:
	int addRule(const QString &ip, const QString &table);
	int deleteRule(const QString &ip, const QString &table);
	void addRoute(const QString &iface, const QString &ip, const QString &table);
	void deleteRoute(const QString &iface, const QString &ip, const QString &table);
	QStringList iptablesParsing(const QString &cmd);
	int deleteTableRule(const QString &table);
private:
	ApplicationSettings *appset;
	DhcpServerInfo *dserver;
	PcapAnalyze *analyze;
	TcpServer *tcp;
	QProcess *p;
	QStringList iplist;
	QString vlanno;
	QString personalgrp;
	QTimer *timer;
	QString ip;
	QString mac;
};

#endif // LOADBALANCING_H
