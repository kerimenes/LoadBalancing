#include "loadbalancing.h"

#include <QProcess>
#include <QDebug>
#include <QTimer>
#include <QFile>

#define iface1 "192.168.1.14"
#define iface2 "192.168.3.14"
#define iface3 "192.168.4.14"

#define standartused "standartused"
#define commonlyused "commonlyused"
#define rarelyused  "rarelyused"

LoadBalancing::LoadBalancing(QObject *parent)
{
	appset = ApplicationSettings::instance();
	appset->load("loadbalancing.json",QIODevice::ReadWrite);

	init();

	analyze = NULL;
	timer = new QTimer();
	connect(timer, SIGNAL(timeout()), SLOT(timeout()));
	timer->start(1000);
}

void LoadBalancing::timeout()
{
	gettingNetworkData();
//	networkStateInfo();
}

void LoadBalancing::gettingNetworkData()
{
	QString iface = appset->get("pcap.interface").toString();
	QString pcapstate = appset->get("pcap.status").toString();
	QString logpath = appset->get("pcap.log_path").toString();
	qDebug() << "next1";
	if (!analyze)
		if (pcapstate != "stop") {
			analyze = new PcapAnalyze(iface);
			if (analyze != NULL)
				logFile(logpath," Pcap Started");
		}
	qDebug() << "next2";
}

void LoadBalancing::gettingData(QByteArray data)
{
	qDebug() << "next3";
	QStringList flds = QString (data.data()).split(" ");

	foreach (QString tmp, flds) {
		if (tmp.split(".").size() > 3)
			ip = tmp;
		if (tmp.split(":").size() > 5) {
			tmp.replace("\n", "");
			mac = tmp;
		}
	}
	qDebug() << "next4";

	logFile(appset->get("pcap.log_path").toString(),QString("%1 ~ %2").arg(ip).arg(mac));

	QHash <QString, QString> lease;
	lease.insert(ip, mac);

	checkMacAdress(lease);
	qDebug() << "next5";
}

void LoadBalancing::splitIP()
{
	foreach (const QString &ip, iplist) {
		QStringList flds = ip.split(".");
		if (flds.size() > 3) {
			vlanno = flds.at(1);
			personalgrp = flds.at(2);
		}
		qDebug() << vlanno << personalgrp;
		//		checkIPruleList(ip);
	}
}

void LoadBalancing::checkMacAdress(QHash<QString, QString> lease)
{
	QString ruletype = standartused;

	if (ruletype == standartused) {
		QString macfilepath = appset->get("mac.0.file1").toString();
		QString type = appset->get("mac.0.ruletype").toString();
		if (!macfilepath.isEmpty())
			ruletype = checkMACfile(macfilepath, lease, type);
	}
	if (ruletype == standartused) {
		QString macfilepath = appset->get("mac.1.file2").toString();
		QString type = appset->get("mac.1.ruletype").toString();
		if (!macfilepath.isEmpty())
			ruletype = checkMACfile(macfilepath, lease, type);
	}
	if (ruletype == standartused) {
		QString macfilepath = appset->get("mac.2.file2").toString();
		QString type = appset->get("mac.2.ruletype").toString();
		if (!macfilepath.isEmpty())
			ruletype = checkMACfile(macfilepath, lease, type);
	}
	if (ruletype == standartused) {
		QString macfilepath = appset->get("mac.3.file3").toString();
		QString type = appset->get("mac.3.ruletype").toString();
		if (!macfilepath.isEmpty())
			ruletype = checkMACfile(macfilepath, lease, type);
	}
	checkIPruleList(ip, ruletype);
}

QString LoadBalancing::checkMACfile(const QString &macpath, QHash<QString, QString> lease, QString type)
{
	QString ruletype = standartused;
	QFile macFile(macpath);
	if (!macFile.open(QIODevice::ReadOnly | QIODevice::Text))
		return "";

	while (!macFile.atEnd()) {
		QString tmp = macFile.readLine().data();
		tmp.replace("\n","");

		if (tmp == lease.value(ip)) {
			ruletype = type;
			break;
		} else ruletype = standartused;
	}
	logFile(appset->get("pcap.log_path").toString(), QString("%1 ~ %2").arg(macpath).arg(ruletype));
	macFile.close();
	return ruletype;
}

void LoadBalancing::checkIPruleList(const QString &ip, const QString &table)
{
	QProcess p;
	p.start("ip rule show");
	p.waitForFinished(2000);
	QString tmp = p.readAllStandardOutput().data();

	QString defIP;
	QString defTable;

	QStringList flds;
	foreach (QString line, tmp.split("\n")) {
		flds << line.split("\t").at(1);
	}

	QString temp;
	QHash<QString, QString> iprule;
	int numberoflist = 0;
	int nolist = 0;
	foreach (QString line, flds) {
		temp = line.split(" ").at(1);
		if (temp.split(".").size() > 3)
			defIP = temp;

		temp = line.split(" ").at(3);
		if (temp.size() > 9)
			defTable = temp;

		if (ip != defIP) {
			nolist++;
		}
		if (ip == defIP & table != defTable) {
			addRule(ip, table);
			for (int i = 0; i < 10; i ++)
				deleteRule(ip, defTable);
		}

		if (ip == defIP &  table == defTable) {
			numberoflist ++;
			for (int i = 1; i < numberoflist; i++)
				deleteRule(ip, table);
		}
	}
	if (nolist == flds.size())
		addRule(ip, table);
	//	addRule(ip, table);
}

void LoadBalancing::checkIPstatus(const QString &ip)
{
	QStringList flds = ip.split(".");
	if (flds.size() > 3) {
		vlanno = flds.at(1);
		personalgrp = flds.at(2);
	}
	if (personalgrp.toInt() <= 99) {
		addRule(ip, rarelyused);
	} else if (personalgrp.toInt() > 99 & personalgrp.toInt() <= 199) {
		addRule(ip, commonlyused);
	} else if (personalgrp.toInt() > 199 & personalgrp.toInt() <=255) {
		addRule(ip, standartused);
	}

#ifdef statement
	if ((vlanno == "10") & (personalgrp <= "199")) {
		addRule(ip, rarelyused);
	} else if (vlanno == "10" & personalgrp > "199") {
		addRule(ip, standartused);
	}

	if (vlanno == "20" & personalgrp <= "199") {
		addRule(ip, rarelyused);
	} else if (vlanno == "20" & personalgrp > "199") {
		addRule(ip, standartused);
	}

	if (vlanno == "30" & personalgrp <= "199") {
		addRule(ip, rarelyused);
	} else if (vlanno == "30" & personalgrp > "199") {
		addRule(ip, standartused);
	}

	if (vlanno == "40" & personalgrp <= "199") {
		addRule(ip, rarelyused);
	} else if (vlanno == "40" & personalgrp > "199") {
		addRule(ip, standartused);
	}

	if (vlanno == "50" & personalgrp <= "199") {
		addRule(ip, rarelyused);
	} else if (vlanno == "50" & personalgrp > "199") {
		addRule(ip, standartused);
	}

	if (vlanno == "60" & personalgrp <= "199") {
		addRule(ip, rarelyused);
	} else if (vlanno == "60" & personalgrp > "199") {
		addRule(ip, standartused);
	}

	if (vlanno == "70" & personalgrp <= "199") {
		addRule(ip, rarelyused);
	} else if (vlanno == "70" & personalgrp > "199") {
		addRule(ip, standartused);
	}

	if (vlanno == "80" & personalgrp <= "199") {
		addRule(ip, rarelyused);
	} else if (vlanno == "80" & personalgrp > "199") {
		addRule(ip, standartused);
	}

	if (vlanno == "90" & personalgrp <= "199") {
		addRule(ip, rarelyused);
	} else if (vlanno == "90" & personalgrp > "199") {
		addRule(ip, standartused);
	}
#endif
}

void LoadBalancing::init()
{
	tcp = new TcpServer(this);
	if (tcp->listen(QHostAddress::Any, 8978))
		connect(tcp, SIGNAL(newDataAvailable(QByteArray)), this, SLOT(gettingData(QByteArray)));
	else qDebug() << "not Connection";

}

QHash <QString, float> LoadBalancing::networkStateInfo()
{
	QHash <QString, float> ifacedownload;
	ifacedownload.insert(iface1, analyze->getDstIPStats("192.168.1.14") / 8); // MBYTE;
	ifacedownload.insert(iface2, analyze->getDstIPStats("192.168.3.14") / 8); // MBYTE;
	ifacedownload.insert(iface3, analyze->getDstIPStats("192.168.4.14") / 8); // MBYTE;

	return ifacedownload;
}

QStringList LoadBalancing::checkISPState()
{
}

int LoadBalancing::addRule(const QString &ip, const QString &table)
{
	logFile(appset->get("pcap.log_path").toString(),QString("Adding table %1 ~ %2").arg(ip).arg(table));
	QProcess p;
	p.start(QString ("ip rule add from %1 table %2").arg(ip).arg(table));
	if (!p.waitForStarted())
		return -1;
	p.waitForFinished(200);
	qDebug() << p.readAllStandardOutput().size();
	if (p.readAllStandardOutput().size() > 0) {
		qDebug() << "exiting not execute script or command";
		return -1;
	}
}

int LoadBalancing::deleteRule(const QString &ip, const QString &table)
{
	logFile(appset->get("pcap.log_path").toString(),QString("Deleting table %1 ~ %2").arg(ip).arg(table));
	QProcess p;
	p.start(QString ("ip rule delete from %1 table %2").arg(ip).arg(table));
	if (!p.waitForStarted())
		return -1;
	p.waitForFinished(200);
	qDebug() << p.readAllStandardOutput().size();
	if (p.readAllStandardOutput().size() > 0) {
		qDebug() << "exiting not execute script or command";
		return -1;
	}
}

void LoadBalancing::addRoute(const QString &iface, const QString &ip, const QString &table)
{

}

void LoadBalancing::deleteRoute(const QString &iface, const QString &ip, const QString &table)
{

}


void LoadBalancing::logFile(const QString &logpath, const QString &logdata)
{
	QFile log(logpath);
	if (!log.open(QIODevice::ReadWrite | QIODevice::Append))
		return;

	QTextStream out(&log);
	out << logdata << "\n";
	log.close();
}

QStringList LoadBalancing::iptablesParsing(const QString &cmd)
{
	QStringList flds = cmd.split(",");

return flds;
}


int LoadBalancing::iptablesRun(const QStringList &cmd)
{
	QProcess p;
	for (int i = 0; i < cmd.size(); i++)
		p.start(cmd.at(i));
	if (!p.waitForStarted())
		return -1;
	p.waitForFinished(2000);
	qDebug() << p.readAllStandardOutput();
}
