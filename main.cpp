#include <QCoreApplication>

#include <loadbalancing.h>

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);
	LoadBalancing *w = new LoadBalancing();
	return a.exec();
}

