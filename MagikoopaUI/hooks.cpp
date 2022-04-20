#include "hooks.h"
#include "hooklinker.h"
#include "keystone/keystone.h"

quint32 Hook::makeBranchOpcode(quint32 src, quint32 dest, bool link)
{
    quint32 ret = 0xEA000000;
    if (link) ret |= 0x01000000;

    int offset = (dest / 4) - (src / 4) - 2;
    offset &= 0x00FFFFFF;

    ret |= offset;

    return ret;
}

quint32 Hook::offsetOpcode(quint32 opcode, quint32 orgPosition, qint32 newPosition)
{
    quint32 fixedOpcode = opcode;

    quint8 nybble14 = (opcode >> 24) & 0xF;

    // TODO: Add more fixeable opcodes
    //  BX (12/01)
    //  BLX (12/03)

    // Fix Branches (B/BL)
    if (nybble14 >= 0xA && nybble14 <= 0xB)
    {
        fixedOpcode &= 0xFF000000;

        qint32 oldOffset = opcode & 0x00FFFFFF;
        oldOffset = (oldOffset + 2) * 4;

        quint32 dest = orgPosition + oldOffset;

        qint32 newOffset = (dest / 4) - (newPosition / 4) - 2;

        fixedOpcode |= newOffset & 0x00FFFFFF;
    }

    return fixedOpcode;
}

Hook::~Hook()
{
}

void Hook::base(HookLinker* parent, quint32 address)
{
    m_parent = parent;
    m_address = address;
}

BranchHook::BranchHook(HookLinker* parent, quint32 address, QString symbol, BranchType type)
{
    base(parent, address);

    bool ok = true;
    m_destination = parent->symTable()->get(symbol, &ok);
    if (!ok)
        throw new HookException(QString("Function name \"%1\" not found").arg(symbol));
    m_branchType = type;
}

void BranchHook::writeData(FileBase* file, quint32)
{
    file->seek(m_address - 0x00100000);

    union {
        struct {
            signed int relAddr : 24;
            quint8 type : 8;
        };
        quint32 data;
    } conv { { static_cast<signed int>((m_destination - m_address - 8) / 4), (quint8)m_branchType } };

    file->write32(conv.data);
}

SoftBranchHook::SoftBranchHook(HookLinker* parent, quint32 address, Opcode_Pos opcode, const QString& symbol)
{
    base(parent, address);
    m_opcodePos = opcode;

    bool ok;
    m_destination = parent->symTable()->get(symbol, &ok);

    if (!ok)
        throw new HookException(QString("Symbol name \"%1\" not found").arg(symbol));

    /*if (info->has("func"))
    {
        if (!parent->symTable())
            throw new HookExeption(info, "Invalid SymTable");

        bool ok;
        m_destination = parent->symTable()->get(info->get("func"), &ok);

        if (!ok)
            throw new HookExeption(info, QString("Function name \"%1\" not found").arg(info->get("func")));
    }
    else
    {
        if (!info->has("dest"))
            throw new HookExeption(info, "No branch destination given");

        bool ok;
        m_destination = info->getUint("dest", &ok);

        if (!ok)
            throw new HookExeption(info, QString("Invalid branch destination \"%1\"").arg(info->get("dest")));
    }

    if (info->has("opcode"))
    {
        QString opcodePosStr = info->get("opcode").toLower();
        if (opcodePosStr == "pre")
            m_opcodePos = Opcode_Pre;
        else if (opcodePosStr == "post")
            m_opcodePos = Opcode_Post;
        else if (opcodePosStr == "ignore")
            m_opcodePos = Opcode_Ignore;
        else
            throw new HookExeption(info, QString("Invalid softHook opcode position \"%1\"").arg(info->get("opcode")));
    }
    else
        m_opcodePos = Opcode_Ignore;*/
}

void SoftBranchHook::writeData(FileBase* file, quint32 extraDataPtr)
{
    file->seek(m_address - 0x00100000);
    quint32 originalOpcode = file->read32();            // This breaks position dependent opcodes
    file->seek(m_address - 0x00100000);
    file->write32(makeBranchOpcode(m_address, extraDataPtr, false));

    file->seek(extraDataPtr - 0x00100000);
    if (m_opcodePos == Opcode_Pre) file->write32(offsetOpcode(originalOpcode, m_address, file->pos() + 0x00100000));
    file->write32(0xE92D5FFF);      //push {r0-r12, r14}
    file->write32(makeBranchOpcode(file->pos() + 0x00100000, m_destination, true));
    file->write32(0xE8BD5FFF);      //pop {r0-r12, r14}
    if (m_opcodePos == Opcode_Post) file->write32(offsetOpcode(originalOpcode, m_address, file->pos() + 0x00100000));
    file->write32(makeBranchOpcode(file->pos() + 0x00100000, m_address + 4, false));
}

PatchHook::PatchHook(HookLinker* parent, quint32 address, const QString& data)
{
    base(parent, address);

    QString dataStr = data;
    if (dataStr.startsWith("0x"))
        dataStr = data.mid(2);

    dataStr.replace(' ', "");
    dataStr.replace('\t', "");

    m_patchData = QByteArray::fromHex(dataStr.toLatin1());
    if (m_patchData.size() == 0)
        throw new HookException("No patch data given");
}

void PatchHook::writeData(FileBase* file, quint32)
{
    file->seek(m_address - 0x00100000);
    file->writeData((quint8*)m_patchData.data(), m_patchData.size());
}

SymbolAddrPatchHook::SymbolAddrPatchHook(HookLinker* parent, quint32 address, const QString& symbol)
{
    base(parent, address);

    bool ok;
    m_destination = parent->symTable()->get(symbol, &ok);

    if (!ok)
        throw new HookException(QString("Symbol name \"%1\" not found").arg(symbol));
}

void SymbolAddrPatchHook::writeData(FileBase* file, quint32)
{
    file->seek(m_address - 0x00100000);
    file->write32(m_destination);
}

SymbolDataPatchHook::SymbolDataPatchHook(HookLinker* parent, quint32 address, const QString& symbol, quint32 len)
    : m_size(len)
{
    base(parent, address);

    bool ok;
    m_dataPtr = parent->symTable()->get(symbol, &ok);

    if (!ok)
        throw new HookException(QString("Symbol name \"%1\" not found").arg(symbol));
}

void SymbolDataPatchHook::writeData(FileBase* file, quint32)
{
    file->seek(m_dataPtr - 0x00100000);
    quint8* writeData = new quint8[m_size];
    file->readData(writeData, m_size);
    file->seek(m_address);
    file->writeData(writeData, m_size);
    delete[] writeData;
}

AssemblerHook::AssemblerHook(HookLinker* parent, quint32 address, const QString& data)
{
    base(parent, address);
    ks_engine* ks;
    ks_err err = ks_open(KS_ARCH_ARM, KS_MODE_ARM, &ks);
    if (err != KS_ERR_OK)
        throw std::runtime_error("Failed initializing Keystone Engine");

    size_t count = 1;
    if (ks_asm(ks, data.toLatin1().constData(), m_address, &m_data, &m_size, &count) != KS_ERR_OK)
        throw new HookException(QString().sprintf("Assembler failed to assemble '%s':%zu with message '%s'",
            data.toLatin1().constData(), count, ks_strerror(ks_errno(ks))));
    ks_close(ks);
}

void AssemblerHook::writeData(FileBase* file, quint32)
{
    file->seek(m_address - 0x00100000);
    file->writeData(m_data, m_size);

    ks_free(m_data);
}
