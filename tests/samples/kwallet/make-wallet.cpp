// Make real KWallet wallet files with KWallet's own backend library, as ksecretd/kwalletd does:
//   make-wallet NAME PASSWORD     ($XDG_DATA_HOME/kwalletd/NAME.kwl and NAME.salt)
// then check they open with that password and not with another.
#include <QCoreApplication>
#include <cstdio>
#include "kwalletbackend.h"
#include "kwalletentry.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString name = QString::fromUtf8(argv[1]);
    const QByteArray pass(argv[2]);
    {
        KWallet::Backend be(name);
        be.setCipherType(KWallet::BACKEND_CIPHER_BLOWFISH);     // as ksecretd does for a new wallet
        int rc = be.open(pass);
        printf("create %s: open %d\n", argv[1], rc);
        be.createFolder(QStringLiteral("Passwords"));
        be.setFolder(QStringLiteral("Passwords"));
        KWallet::Entry e;
        e.setKey(QStringLiteral("example.org"));
        e.setValue(QByteArray("not-a-real-secret"));
        e.setType(KWallet::Wallet::Password);
        be.writeEntry(&e);
        printf("close(save) %d\n", be.close(true));
    }
    {
        KWallet::Backend be(name);
        printf("reopen with its password: %d\n", be.open(pass));
    }
    {
        KWallet::Backend be(name);
        printf("reopen with another: %d\n", be.open(QByteArray("wrong password")));
    }
    return 0;
}
