#include <vector>
#include <string>
#include <iostream>
#include <span>
#include <tdscpp.h>
#include "aes.h"

using namespace std;

struct project {
    project(int64_t id, string_view name, span<const uint8_t> data) : id(id), name(name) {
        this->data.assign(data.begin(), data.end());
    }

    int64_t id;
    string name;
    vector<uint8_t> data;
};

static void dump_ssis(string_view db_server, string_view db_username, string_view db_password) {
    vector<project> projs;

    tds::tds tds(db_server, db_username, db_password, "ssisdump", "SSISDB");

    {
        tds::query sq(tds, "SELECT internal.get_encryption_algorithm()");

        if (!sq.fetch_row())
            throw runtime_error("SSISDB.internal.get_encryption_algorithm returned no value.");

        auto s = (string)sq[0];

        if (s != "AES_256")
            throw runtime_error("Unknown encryption algorithm " + s + ".");
    }

    // FIXME - folders

    {
        tds::query sq(tds, R"(SELECT projects.project_id,
    projects.name,
    object_versions.object_data
FROM catalog.projects
JOIN internal.object_versions ON object_versions.object_id = projects.project_id AND
    object_versions.object_version_lsn = projects.object_version_lsn)");

        while (sq.fetch_row()) {
            projs.emplace_back((int64_t)sq[0], (string)sq[1], sq[2].val);
        }
    }

    for (auto& p : projs) {
        vector<uint8_t> key;
        vector<uint8_t> iv;
        AES_ctx ctx;

        const auto& key_name = "MS_Enckey_Proj_"s + to_string(p.id);

        tds.run(tds::no_check{"OPEN SYMMETRIC KEY " + key_name + " DECRYPTION BY CERTIFICATE MS_Cert_Proj_" + to_string(p.id)});

        {
            tds::query sq(tds, "SELECT DECRYPTBYKEY([key]), DECRYPTBYKEY(IV) FROM internal.catalog_encryption_keys WHERE key_name = ?", key_name);

            if (!sq.fetch_row())
                throw runtime_error("Could not find key " + key_name + " in SSISDB.internal.catalog_encryption_keys.");

            key.assign(sq[0].val.begin(), sq[0].val.end());
            iv.assign(sq[1].val.begin(), sq[1].val.end());
        }

        tds.run(tds::no_check{"CLOSE SYMMETRIC KEY " + key_name});

        AES256_init_ctx_iv(&ctx, key.data(), iv.data());
        AES256_CBC_decrypt_buffer(&ctx, p.data.data(), p.data.size());
    }

    // FIXME - unzip
    // FIXME - Git
}

int main(int argc, char* argv[]) {
    vector<string> args;
    string db_server, db_username, db_password;

    args.reserve(argc);

    for (int i = 0; i < argc; i++) {
        args.emplace_back(argv[i]);
    }

    if (argc >= 2)
        db_server = args[1];

    if (db_server.empty()) {
        cerr << "Usage: ssisdump <server>" << endl;
        return 1;
    }

    if (getenv("DB_USERNAME"))
        db_username = getenv("DB_USERNAME");

    if (getenv("DB_PASSWORD"))
        db_password = getenv("DB_PASSWORD");

    try {
        dump_ssis(db_server, db_username, db_password);
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}
