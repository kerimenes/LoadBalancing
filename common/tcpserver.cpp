#include "tcpserver.h"

#include <QHostAddress>
#include <QTcpSocket>

TcpServer::TcpServer(QObject *parent) :
	QObject(parent)
{
	tcpserver = new QTcpServer();
}

int TcpServer::listen(QHostAddress address, quint16 port)
{
	connect(tcpserver, SIGNAL(newConnection()), SLOT(newConnection()));

	bool state = tcpserver->listen(address, port);
	if (!state)
		return 0;
	return 1;
}

void TcpServer::newConnection()
{
	sock = tcpserver->nextPendingConnection();
	QString peeraddress = sock->peerAddress().toString().split(":").at(3);
	if (peeraddress != "10.30.1.254") {
		sock->deleteLater();
		qDebug() << "not accept to this host" << peeraddress;
		return;
	}
	connect(sock, SIGNAL(disconnected()), SLOT(clientDisconnected()));
	connect(sock, SIGNAL(readyRead()), SLOT(newData()));
}

void TcpServer::clientDisconnected()
{
	qDebug() << "Disconnected";
	sock->deleteLater();
}

void TcpServer::newData()
{
	QByteArray data;
	qDebug() << sock->bytesAvailable() << "Sock BytesAvailable";
	while (sock->bytesAvailable()) {
		data = sock->readAll();
		qDebug() << "New Data:" << data;
		emit newDataAvailable(data);
	}
	return;
}
