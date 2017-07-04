#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QAbstractSocket>

class TcpServer : public QObject
{
	Q_OBJECT
public:
	TcpServer(QObject *parent = 0);
	int listen(QHostAddress address, quint16 port);

signals:
	void newDataAvailable(const QByteArray &data);

public slots:
	void newConnection();
	void clientDisconnected();
	void newData();

private:
	QTcpServer* tcpserver;
	QTcpSocket *sock ;
};

#endif // TCPSERVER_H
