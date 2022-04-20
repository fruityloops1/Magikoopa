#ifndef HOOKS_H
#define HOOKS_H

#include "symtable.h"
#include "Filesystem/filesystem.h"

#include "hooklinker.h"
#include <QByteArray>
#include <exception>

class HookLinker;

// Extradata | Code | Symbols

enum class BranchType : quint8 {
    B = 0xEA,
    BL = 0xEB,
    BEQ = 0x0A,
    BNE = 0x1A,
    BCS = 0x2A,
    BCC = 0x3A,
    BMI = 0x4A,
    BPL = 0x5A,
    BVS = 0x6A,
    BVC = 0x7A,
    BHI = 0x8A,
    BLS = 0x9A,
    BGE = 0xAA,
    BLT = 0xBA,
    BGT = 0xCA,
    BLE = 0xDA,
    BAL = 0xEA,
    BLX = 0xFA,
    BLEQ = 0x0B,
    BLNE = 0x1B,
    BLCS = 0x2B,
    BLCC = 0x3B,
    BLMI = 0x4B,
    BLPL = 0x5B,
    BLVS = 0x6B,
    BLVC = 0x7B,
    BLHI = 0x8B,
    BLLS = 0x9B,
    BLGE = 0xAB,
    BLLT = 0xBB,
    BLGT = 0xCB,
    BLLE = 0xDB,
    BLAL = 0xEB
};

const QHash<QString, BranchType> branchStringToType = {
    { "b", BranchType::B },
    { "bl", BranchType::BL },
    { "beq", BranchType::BEQ },
    { "bne", BranchType::BNE },
    { "bcs", BranchType::BCS },
    { "bcc", BranchType::BCC },
    { "bmi", BranchType::BMI },
    { "bpl", BranchType::BPL },
    { "bvs", BranchType::BVS },
    { "bvc", BranchType::BVC },
    { "bhi", BranchType::BHI },
    { "bls", BranchType::BLS },
    { "bge", BranchType::BGE },
    { "blt", BranchType::BLT },
    { "bgt", BranchType::BGT },
    { "ble", BranchType::BLE },
    { "bal", BranchType::BAL },
    { "bleq", BranchType::BLEQ },
    { "blne", BranchType::BLNE },
    { "blcs", BranchType::BLCS },
    { "blcc", BranchType::BLCC },
    { "blmi", BranchType::BLMI },
    { "blpl", BranchType::BLPL },
    { "blvs", BranchType::BLVS },
    { "blvc", BranchType::BLVC },
    { "blhi", BranchType::BLHI },
    { "blls", BranchType::BLLS },
    { "blge", BranchType::BLGE },
    { "bllt", BranchType::BLLT },
    { "blgt", BranchType::BLGT },
    { "blle", BranchType::BLLE },
    { "blal", BranchType::BLAL },
};

class Hook
{
public:
    virtual ~Hook();

    virtual void writeData(FileBase*, quint32) {}

    virtual quint32 extraDataSize() { return 0; }
    virtual quint32 overwriteSize() { return 0; }

protected:
    Hook() {}
    void base(HookLinker* parent, quint32 address);

    static quint32 makeBranchOpcode(quint32 src, quint32 dest, bool link);
    static quint32 offsetOpcode(quint32 opcode, quint32 orgPosition, qint32 newPosition);

    QString m_name;
    quint32 m_address;
    QByteArray m_data;

    HookLinker* m_parent;
};


class BranchHook : public Hook
{
public:
    BranchHook(HookLinker* parent, quint32 address, QString symbol, BranchType type);
    void writeData(FileBase* file, quint32 extraDataPos);
    quint32 overwriteSize() override { return 4; }

private:
    BranchType m_branchType;
    quint32 m_destination;
};

class SoftBranchHook : public Hook
{
public:
    enum Opcode_Pos { Opcode_Ignore,
        Opcode_Pre,
        Opcode_Post };
    SoftBranchHook(HookLinker* parent, quint32 address, Opcode_Pos opcode, const QString& symbol);
    void writeData(FileBase* file, quint32 extraDataPtr) override;
    quint32 extraDataSize() override { return 5 * 4; }
    quint32 overwriteSize() override { return 4; }

private:
    Opcode_Pos m_opcodePos;
    quint32 m_destination;
};


class PatchHook : public Hook
{
public:
    PatchHook(HookLinker* parent, quint32 address, const QString& data);
    void writeData(FileBase* file, quint32 extraDataPos) override;
    quint32 overwriteSize() override { return m_patchData.size(); }

private:
    QByteArray m_patchData;
};


class SymbolAddrPatchHook : public Hook
{
public:
    SymbolAddrPatchHook(HookLinker* parent, quint32 address, const QString& symbol);
    void writeData(FileBase* file, quint32 extraDataPos) override;
    quint32 overwriteSize() override { return 4; }

private:
    quint32 m_destination;
};

class SymbolDataPatchHook : public Hook {
public:
    SymbolDataPatchHook(HookLinker* parent, quint32 address, const QString& symbol, quint32 len);
    void writeData(FileBase* file, quint32 extraDataPos) override;
    quint32 overwriteSize() override { return m_size; }

private:
    quint32 m_dataPtr;
    quint32 m_size;
};

#endif // HOOKS_H
