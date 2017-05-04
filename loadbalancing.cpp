#include "loadbalancing.h"

#include <QProcess>
#include <QDebug>
#include <QTimer>
#include <QFile>

#define iface1 "192.168.1.14"
#define iface2 "192.168.3.14"
#define iface3 "192.168.4.14"

#define rarelyused  "T3"
#define standartused "T1"
#define commonlyused "T2"

//dserver = new DhcpServerInfo();
//iplist = dserver->getIPList();
//	splitIP();

LoadBalancing::LoadBalancing(QObject *parent)
{
	analyze = new PcapAnalyze("enp3s0f1");
	qDebug() << analyze;

	init();


	timer = new QTimer();
	connect(timer, SIGNAL(timeout()), SLOT(timeout()));
	timer->start(1000);
}

void LoadBalancing::timeout()
{
//	networkStateInfo();
	//	checkISPState();
	//	timer->setInterval(1000);
}

void LoadBalancing::gettingData(QByteArray data)
{
	QStringList flds = QString (data.data()).split(" ");

	foreach (QString tmp, flds) {
		if (tmp.split(".").size() > 3)
			ip = tmp;
		if (tmp.split(":").size() > 5) {
			tmp.replace("\n", "");
			mac = tmp;
		}
	}
	qDebug() << ip << mac;

	QHash <QString, QString> lease;
	lease.insert(ip, mac);

	checkMacAdress(lease);
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
		checkIPruleList(ip);
	}
}

void LoadBalancing::checkMacAdress(QHash<QString, QString> lease)
{
	QString ruletype = standartused;

	QFile macFileA("mac_bilkonA.txt");
	if (!macFileA.open(QIODevice::ReadOnly | QIODevice::Text))
		return;

	while (!macFileA.atEnd()) {
		QString tmp = macFileA.readLine().data();
		tmp.replace("\n","");

		if (tmp == lease.value(ip)) {
			ruletype = rarelyused;
			break;
		} else ruletype = standartused;
	}
	qDebug() << "Mac_file_A" << ruletype;
	macFileA.close();


	QFile macFileB("mac_bilkonB.txt");
	if (!macFileB.open(QIODevice::ReadOnly | QIODevice::Text))
		return;

	while (!macFileB.atEnd()) {
		QString tmp = macFileB.readLine().data();
		tmp.replace("\n","");

		if (ruletype != standartused)
			break;

		if (tmp == lease.value(ip)) {
			ruletype = commonlyused;
			break;
		} else ruletype = standartused;
	}
	macFileB.close();

	addRule(ip, ruletype);
}

void LoadBalancing::checkIPruleList(const QString &ip)
{
	QProcess p;
	p.start("ip rule show");
	p.waitForFinished(2000);
	QString tmp = p.readAllStandardOutput().data();
	if (!tmp.contains(ip)) {

	}
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

void LoadBalancing::networkStateInfo()
{
	ifacedownload.insert(iface1, analyze->getDstIPStats("192.168.1.14") / 8); // MBYTE;
	ifacedownload.insert(iface2, analyze->getDstIPStats("192.168.3.14") / 8); // MBYTE;
	ifacedownload.insert(iface3, analyze->getDstIPStats("192.168.4.14") / 8); // MBYTE;
	qDebug() << ifacedownload.values().at(0) << ifacedownload.values().at(1) << ifacedownload.values().at(2);
}

QStringList LoadBalancing::checkISPState()
{
}

int LoadBalancing::addRule(const QString &ip, const QString &table)
{
	qDebug() << "add rule" << ip << table;
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


