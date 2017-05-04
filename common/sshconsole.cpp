#include "sshconsole.h"

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <QFuture>
#include <QFileInfo>
#include <QtConcurrentRun>
#include <QCoreApplication>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <ecl/debug.h>

SshConsole::SshConsole(QObject *parent) :
	QObject(parent)
{
	ses = NULL;

	connect(&watcher, SIGNAL(finished()), SLOT(handleFinished()));
}

SshConsole::~SshConsole()
{
	if (ses) {
		ssh_disconnect(ses);
		ssh_free(ses);
		ses = NULL;
	}
}

int SshConsole::connectToHost(QHostAddress target)
{
	ses = ssh_new();
	if (!ses)
		return -EPERM;

	ssh_options_set(ses, SSH_OPTIONS_HOST, qPrintable(target.toString()));
	//ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	//ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);

	int err = ssh_connect(ses);
	if (err != SSH_OK) {
		mDebug("error connecting ssh session: '%s'", ssh_get_error(ses));
		goto err_out;
	}

	if (privateKeyFilename.isEmpty()) {
		err = ssh_userauth_password(ses, qPrintable(user), qPrintable(pass));
	} else {
		ssh_key prikey;
		err = ssh_pki_import_privkey_file(qPrintable(privateKeyFilename), NULL, NULL, NULL, &prikey);
		if (err != SSH_OK) {
			mDebug("error importing private key");
			goto err_out;
		}
		err = ssh_userauth_publickey(ses, "root", prikey);
	}
	if (err != SSH_AUTH_SUCCESS) {
		mDebug("error authenticating to server");
		goto err_out;
	}

	return 0;

err_out:
	ssh_free(ses);
	ses = NULL;

	return err;
}

int SshConsole::executeCommands(const QStringList &list, QStringList &output)
{
	if (!ses)
		return -ENOENT;
	ssh_channel ch = ssh_channel_new(ses);
	if (!ch)
		return -EPERM;
	int err = ssh_channel_open_session(ch);
	if (err != SSH_OK)
		return err;
	err = ssh_channel_request_shell(ch);
	if (err != SSH_OK)
		return err;
	mInfo("shell requested");
	for (int i = 0; i < list.size(); i++) {
		QString cmd = list[i];
		cmd.append("\n");
		int written = ssh_channel_write(ch, qPrintable(cmd), cmd.size());
		if (written != cmd.size()) {
			mDebug("error sending command '%s'", qPrintable(cmd));
			return -EINVAL;
		}
		QString resp;
		char buffer[1024];
		int bytes = ssh_channel_read_timeout(ch, buffer, sizeof(buffer), 0, 1000);
		while (bytes > 0) {
			qDebug() << bytes;
			resp.append(QString::fromUtf8(buffer, bytes));
			bytes = ssh_channel_read_timeout(ch, buffer, sizeof(buffer), 0, 1000);
		}
		output << resp.trimmed();
	}

	ssh_channel_send_eof(ch);
	ssh_channel_close(ch);
	ssh_channel_free(ch);

	return 0;
}

int SshConsole::executeCommand(const QString &cmd, QString &response)
{
	if (!ses)
		return -ENOENT;
	ssh_channel ch = ssh_channel_new(ses);
	if (!ch)
		return -EPERM;
	int err = ssh_channel_open_session(ch);
	if (err != SSH_OK)
		return err;

	err = ssh_channel_request_exec(ch, qPrintable(cmd));
	if (err != SSH_OK) {
		mDebug("error executing command '%s'", qPrintable(cmd));
		ssh_channel_close(ch);
		ssh_channel_free(ch);
		return err;
	}
	QString resp;
	char buffer[1024];
	int bytes = ssh_channel_read(ch, buffer, sizeof(buffer), 0);
	while (bytes > 0) {
		resp.append(QString::fromUtf8(buffer, bytes));
		bytes = ssh_channel_read(ch, buffer, sizeof(buffer), 0);
	}
	response = resp.trimmed();

	ssh_channel_send_eof(ch);
	ssh_channel_close(ch);
	ssh_channel_free(ch);

	return 0;
}

int SshConsole::scp(const QString &filename, const QString &remoteName)
{
	QFileInfo finfo(filename);
	if (!ses)
		return -ENOENT;
	ssh_scp scp = ssh_scp_new(ses, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, qPrintable(remoteName));
	if (!scp)
		return -EPERM;
	int err = ssh_scp_init(scp);
	if (err != SSH_OK) {
		mDebug("error %d init'ing scp session", err);
		qDebug() << ssh_get_error(ses);
		ssh_scp_free(scp);
		return err;
	}
	err = ssh_scp_push_file(scp, qPrintable(finfo.fileName()), finfo.fileName().length(), S_IRUSR | S_IWUSR);
	if (err != SSH_OK) {
		mDebug("error pushing file to remote host");
		ssh_scp_free(scp);
		return err;
	}
	QFile f(finfo.absoluteFilePath());
	if (f.open(QIODevice::ReadOnly)) {
		mDebug("error reading file from filesystem");
		ssh_scp_free(scp);
		return err;
	}
	const QByteArray ba = f.readAll();
	f.close();
	err = ssh_scp_write(scp, ba.constData(), ba.size());
	if (err != SSH_OK) {
		mDebug("error wrting file contents to remote host");
		ssh_scp_free(scp);
		return err;
	}

	return 0;
}

int SshConsole::sftp(const QString &filename, const QString &remoteName)
{
	QFileInfo finfo(filename);
	if (!ses)
		return -ENOENT;
	sftp_session sftp = sftp_new(ses);
	if (!sftp)
		return -ENOMEM;
	int err = sftp_init(sftp);
	if (err != SSH_OK) {
		mDebug("error init'ing sftp session");
		sftp_free(sftp);
		return err;
	}
	sftp_file file = sftp_open(sftp, qPrintable(remoteName), O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
	if (!file) {
		mDebug("error opening remote sftp file '%s'", qPrintable(remoteName));
		sftp_free(sftp);
		return -EPERM;
	}
	QFile f(finfo.absoluteFilePath());
	if (!f.open(QIODevice::ReadOnly)) {
		mDebug("error reading file from filesystem");
		sftp_free(sftp);
		return -ENOENT;
	}
	const QByteArray ba = f.readAll();
	f.close();
	QFuture<int> fut = QtConcurrent::run(this, &SshConsole::sftpTxFile, ba, file);
	while (fut.isRunning())
		QCoreApplication::processEvents();
	err = fut.result();//sftpTxFile(ba, file);
	if (err)
		mDebug("error writing file contents to remote host");
	err = sftp_close(file);
	if (err)
		return err;
	sftp_free(sftp);
	return 0;
}

int SshConsole::sftpASync(const QString &filename, const QString &remoteName)
{
	QFileInfo finfo(filename);
	if (!ses)
		return -ENOENT;
	sftp_session sftp = sftp_new(ses);
	if (!sftp)
		return -ENOMEM;
	int err = sftp_init(sftp);
	if (err != SSH_OK) {
		mDebug("error init'ing sftp session");
		sftp_free(sftp);
		return err;
	}
	sftp_file file = sftp_open(sftp, qPrintable(remoteName), O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
	if (!file) {
		mDebug("error opening remote sftp file");
		sftp_free(sftp);
		return -EPERM;
	}
	QFile f(finfo.absoluteFilePath());
	if (!f.open(QIODevice::ReadOnly)) {
		mDebug("error reading file from filesystem");
		sftp_free(sftp);
		return -ENOENT;
	}
	const QByteArray ba = f.readAll();
	f.close();
	QFuture<int> fut = QtConcurrent::run(this, &SshConsole::sftpTxFile, ba, file);
	watcher.setFuture(fut);
	return 0;
}

int SshConsole::sftpRun(const QString &filename, const QString &remoteName)
{
	int err = sftp(filename, remoteName);
	if (err)
		return err;
	QString response;
	err = executeCommand(QString("chmod +x %1").arg(remoteName), response);
	if (err)
		return err;
	return executeCommand(remoteName, response);
}

void SshConsole::setCredentials(const QString &username, const QString &password)
{
	user = username;
	pass = password;
}

void SshConsole::setAuthKey(const QString &username, const QString &filename)
{
	user = username;
	pass = "";
	privateKeyFilename = filename;
}

void SshConsole::handleFinished()
{
	QFuture<int> fut = watcher.future();
	int err = fut.result();
	if (err)
		mDebug("error writing file contents to remote host");
	emit asyncTxCompleted(err);
	/*err = sftp_close(file);
	if (err)
		return err;
	sftp_free(sftp);*/
	//return 0;
}

int SshConsole::sftpTxFile(const QByteArray &ba, sftp_file file)
{
	int off = 0;
	while (off < ba.size()) {
		int size = 4096;
		if (off + size > ba.size())
			size = ba.size() - off;
		int written = sftp_write(file, ba.constData() + off, size);
		if (written != size) {
			fDebug("error writing file contents to remote host, %d != %d", written, ba.size());
			return -EINVAL;
		}
		off += size;
		emit sFtpProgress(off, ba.size());
	}
	return 0;
}
