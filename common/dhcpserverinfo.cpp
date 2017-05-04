#include "dhcpserverinfo.h"
#include "sshconsole.h"
#include <ecl/debug.h>

#include <QHostInfo>
#include <QHostAddress>

#include <errno.h>

DhcpServerInfo::DhcpServerInfo(QObject *parent) :
	QObject(parent)
{
	fetchInfo();
}

const QStringList DhcpServerInfo::getIPList()
{
	if (infoByIp.isEmpty())
		fetchInfo();
	QStringList keys =  infoByIp.keys();
	keys.removeDuplicates();
	keys.sort();
	return keys;
}

const QStringList DhcpServerInfo::getMACList()
{
	if (infoByMac.isEmpty())
		fetchInfo();
	QStringList keys = infoByMac.keys();
	keys.removeDuplicates();
	keys.sort();
	return keys;
}

const QStringList DhcpServerInfo::getTimeList()
{
	if (infoByTime.isEmpty())
		fetchInfo();
	QStringList keys = infoByTime.keys();
	keys.removeDuplicates();
	keys.sort();
	return keys;
}

const QList<QHash<QString, QString> > DhcpServerInfo::getInfoByIP(const QString &ip)
{
	return infoByIp.values(ip);
}

const QList<QHash<QString, QString> > DhcpServerInfo::getInfoByMAC(const QString &mac)
{
	return infoByMac.values(mac);
}

int DhcpServerInfo::fetchInfo()
{
	if (serverIp.isEmpty()) {
		if (QHostAddress("10.50.1.99").isNull()) {
			/* we need name look-up */
			QHostInfo info = QHostInfo::fromName("10.50.1.99");
			if (!info.addresses().isEmpty())
				serverIp = info.addresses().first().toString();
		} else
			serverIp = "10.50.1.99";
	}
	SshConsole ssh;
	ssh.setCredentials("kerim", "qwe");
	if (ssh.connectToHost(QHostAddress(serverIp)))
		return -EINVAL;
	QString resp;
	if (ssh.executeCommand("cat /var/lib/dhcp/dhcpd.leases", resp))
		return -EIO;
	return parseInfo(resp);
}

int DhcpServerInfo::parseInfo(const QString &resp)
{
	const QStringList &lines = resp.split("\n");
	QHash<QString, QString> current;
	foreach (const QString &line, lines) {
		if (line.trimmed().startsWith("#"))
			continue;
		if (line.startsWith("lease")) {
			current.clear();
			current["ip"] = QString(line).remove("lease").remove("{").trimmed();
		} else if (line.startsWith("}")) {
			/* record this entry */
			infoByIp.insert(current["ip"], current);
			infoByMac.insert(current["macaddr"], current);
			infoByTime.insert(current["time"], current);
			current.clear();
		} else if (current.size()) {
			if (line.contains("hardware ethernet"))
				current["macaddr"] = QString(line).remove("hardware ethernet").remove(";").trimmed();
			else if (line.contains("binding state"))
				current["state"] = QString(line).remove("binding state").remove(";").trimmed();
			else if (line.contains("set ddns-fwd-name"))
				current["ddns_name"] = QString(line).remove("set ddns-fwd-name").remove(";").remove("=").trimmed();
			else if (line.contains("client-hostname"))
				current["hostname"] = QString(line).remove("client-hostname").remove(";").trimmed();
			else if (line.contains("starts"))
				current["time"] = QString(line).remove("starts").remove(QDateTime::currentDateTime().toString("yy/MM/dd")).remove(";").remove(1, 6).trimmed();
		}
	}
	return 0;
}
