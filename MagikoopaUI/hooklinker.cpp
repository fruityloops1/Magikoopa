#include "hooklinker.h"
#include "hooks.h"

#include <QDebug>
#include <QDirIterator>
#include <QMessageBox>
#include <cassert>
#include <cctype>

bool isStringHex(const QString& value)
{
    return QRegExp("^[0-9A-Fa-f]+$").indexIn(value.simplified().replace(" ", "")) != -1;
}

Hook* HookLinker::hookFromData(quint32 address, const QString& data)
{
    if (data.startsWith("pb") || data.startsWith("prb") || data.startsWith("pib")) {
        QString branchType = data.split(QRegExp("\\s+"), QString::SkipEmptyParts)[0];
        SoftBranchHook::Opcode_Pos opcode = SoftBranchHook::Opcode_Post;

        QStringList dataTmp = data.split(' ');
        dataTmp.removeAt(0);
        QString symbol = dataTmp.join(' ');

        if (branchType.startsWith("pb"))
            opcode = SoftBranchHook::Opcode_Pos::Opcode_Post;
        else if (branchType.startsWith("prb"))
            opcode = SoftBranchHook::Opcode_Pos::Opcode_Pre;
        else if (branchType.startsWith("pib"))
            opcode = SoftBranchHook::Opcode_Pos::Opcode_Ignore;
        return new SoftBranchHook(this, address, opcode, symbol);
    } else if ((data.toLower().startsWith("0x") && isStringHex(data.mid(2))) || isStringHex(data)) {
        return new PatchHook(this, address, data.simplified().replace(" ", ""));
    } else if (data.startsWith("symdata")) {
        QStringList dataTmp = data.split(' ');
        dataTmp.removeAt(0);
        dataTmp.removeAt(dataTmp.size() - 1);
        QString symbol = dataTmp.join(' ');
        dataTmp = data.split(' ');
        dataTmp.removeAt(0);

        while (dataTmp.size() > 1)
            dataTmp.removeAt(0);
        QString lenStr = dataTmp[0];

        bool ok = true;
        quint32 len = 0;
        if (lenStr.startsWith("0x"))
            len = lenStr.mid(2).toUInt(&ok, 0x10);
        len = lenStr.toUInt(&ok, 10);
        if (!ok)
            emit outputUpdate("Error: invalid length \"" + lenStr + "\"");

        return new SymbolDataPatchHook(this, address, symbol, len);
    } else if (data.startsWith("sym")) {
        QStringList dataTmp = data.split(' ');
        dataTmp.removeAt(0);
        QString symbol = dataTmp.join(' ');
        return new SymbolAddrPatchHook(this, address, symbol);
    } else if (data.split(QRegExp("\\s+"), QString::SkipEmptyParts)[0].startsWith('b')
        && !data.split(QRegExp("\\s+"), QString::SkipEmptyParts)[1].startsWith('#')) {
        QString key = data.split(QRegExp("\\s+"), QString::SkipEmptyParts)[0].toLower();

        if (branchStringToType.find(key) == branchStringToType.end())
            return new AssemblerHook(this, address, data);
        BranchType type = branchStringToType[key];

        QStringList dataTmp = data.split(' ');
        dataTmp.removeAt(0);
        QString symbol = dataTmp.join(' ');

        if (symbol.startsWith("#") || isStringHex(symbol) || symbol.startsWith("0x"))
            return new AssemblerHook(this, address, data);
        return new BranchHook(this, address, symbol, type);
    } else {
        return new AssemblerHook(this, address, data);
    }

    return nullptr;
}

HookLinker::HookLinker(QObject* parent)
    : QObject(parent)
{

}

HookLinker::~HookLinker()
{
    clear();
}

void HookLinker::loadHooks(const QString& path, LoadMode mode)
{
    if (mode == LoadMode::LoadFile)
        loadHooksFromFile(path);

    else
    {
        QDirIterator::IteratorFlag iFlags;
        if (mode == LoadDir)
            iFlags = QDirIterator::NoIteratorFlags;
        else
            iFlags = QDirIterator::Subdirectories;

        QDirIterator dirIt(path, iFlags);
        while (dirIt.hasNext())
        {
            dirIt.next();

            if (dirIt.fileInfo().isFile() &&
                dirIt.fileInfo().suffix() == "hks")
            {
                loadHooksFromFile(dirIt.filePath());
            }
        }
    }
}

void HookLinker::loadHooksFromFile(const QString& path)
{
    QFile f(path);

    if (!f.exists()) return;
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    QTextStream s(&f);

    QList<HookInfo*> entries;

    HookInfo* current = NULL;
    quint32 lineNbr = 0;
    while (!s.atEnd())
    {
        lineNbr++;
        QString line = s.readLine();

        if (line == "" || line.startsWith("//"))
            continue;

        while (line.contains("//"))
            line = line.left(line.indexOf("//"));

        // New Entry
        if (!line.startsWith(' ') && line.contains(':')) {
            bool ok = true;
            QString value = line.left(line.indexOf(':'));
            quint32 addr;
            if (value.startsWith("0x"))
                addr = value.mid(2).toUInt(&ok, 0x10);
            addr = value.toUInt(&ok, 0x10);
            if (!ok)
                emit outputUpdate("Error: invalid address \"" + value + "\"");
            current = new HookInfo(addr, path, lineNbr);
            entries.append(current);
        }

        // Data
        else if (current != NULL) {
            while (line.startsWith('\t') || line.startsWith(' '))
                line = line.mid(1);
            while (line.endsWith('\t') || line.endsWith(' '))
                line.chop(1);

            current->data.push_back(line);
        }
    }

    f.close();

    foreach (HookInfo* info, entries)
    {
        try
        {
            quint32 address = info->address;
            for (const QString& line : info->data) {
                Hook* hk = hookFromData(address, line);
                if (hk) {
                    hooks.append(hk);
                    address += hk->overwriteSize();
                }
            }
            delete info;
        } catch (HookException* e) {
            emit outputUpdate("Error: Hook: " + e->msg());
        }
    }
}

quint32 HookLinker::extraDataSize()
{
    quint32 extraDataSize = 0;

    foreach (Hook* hook, hooks)
        extraDataSize += hook->extraDataSize();

    return extraDataSize;
}

void HookLinker::applyTo(FileBase* file)
{
    quint32 extraDataPtrCurr = m_extraDataPtr;
    foreach (Hook* hook, hooks)
    {
        hook->writeData(file, extraDataPtrCurr);
        extraDataPtrCurr += hook->extraDataSize();
    }
}

void HookLinker::clear()
{
    foreach (Hook* hook, hooks)
        delete hook;

    hooks.clear();
}
