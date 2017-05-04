#ifndef SSHCONSOLE_H
#define SSHCONSOLE_H

#include <QObject>
#include <QHostAddress>
#include <QFutureWatcher>

struct ssh_session_struct;
struct sftp_file_struct;
typedef struct ssh_session_struct* ssh_session;
typedef struct sftp_file_struct* sftp_file;

class SshConsole : public QObject
{
	Q_OBJECT
public:
	explicit SshConsole(QObject *parent = 0);
	~SshConsole();
	int connectToHost(QHostAddress target);
	int executeCommands(const QStringList &list, QStringList &output);
	int executeCommand(const QString &cmd, QString &response);
	int scp(const QString &filename, const QString &remoteName);
	int sftp(const QString &filename, const QString &remoteName);
	int sftpASync(const QString &filename, const QString &remoteName);
	int sftpRun(const QString &filename, const QString &remoteName);
	void setCredentials(const QString &username, const QString &pass);
	void setAuthKey(const QString &username, const QString &filename);
signals:
	void sFtpProgress(int completed, int total);
	void asyncTxCompleted(int);
protected slots:
	void handleFinished();
protected:
	int sftpTxFile(const QByteArray &ba, sftp_file file);

	ssh_session ses;
	QString user;
	QString pass;
	QString privateKeyFilename;
	QFutureWatcher<int> watcher;
};

#endif // SSHCONSOLE_H
