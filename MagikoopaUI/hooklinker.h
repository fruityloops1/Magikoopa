#ifndef HOOKLINKER_H
#define HOOKLINKER_H

#include "Filesystem/filesystem.h"
#include "symtable.h"

#include <QObject>
#include <QDebug>

class Hook;

struct HookInfo
{
    HookInfo() {}
    HookInfo(quint32 address, const QString& path, quint32 line)
        : address(address)
        , path(path)
        , line(line)
    {
    }

    quint32 address;
    QString path;
    quint32 line;
    QVector<QString> data;
};

class HookException : public std::exception {
public:
    HookException(const QString& msg)
    {
        m_msg = msg;
    }

    const QString& msg() { return m_msg; }

    virtual const char* what() const throw()
    {
        return m_msg.toLatin1().data();
    }

private:
    QString m_msg;
};

class HookLinker : public QObject
{
    Q_OBJECT
public:
    explicit HookLinker(QObject* parent = nullptr);
    ~HookLinker();

    enum LoadMode { LoadFile, LoadDir, LoadSubdirs };
    void loadHooks(const QString& path, LoadMode mode = LoadSubdirs);

    void setExtraDataptr(quint32 extraDataPtr) { m_extraDataPtr = extraDataPtr; }
    quint32 extraDataSize();

    void setSymTable(SymTable* symTable) { m_symTable = symTable; }
    SymTable* symTable() { return m_symTable; }

    Hook* hookFromData(quint32 address, const QString& data);

    void applyTo(FileBase* file);
    void clear();

signals:
    void outputUpdate(QString text);

private:
    SymTable* m_symTable = NULL;

    void loadHooksFromFile(const QString& path);

    QList<Hook*> hooks;

    quint32 m_extraDataPtr;
};

#endif // HOOKLINKER_H
