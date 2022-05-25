#include <vector>
#include <string>
#include <iostream>
#include <span>
#include <tdscpp.h>
#include <archive.h>
#include <archive_entry.h>
#include "aes.h"

using namespace std;

struct project {
    project(int64_t id, span<const uint8_t> data) : id(id) {
        this->data.assign(data.begin(), data.end());
    }

    int64_t id;
    vector<uint8_t> data;
    vector<pair<string, vector<uint8_t>>> files;
};

class archive_closer {
public:
    typedef archive* pointer;

    void operator()(archive* a) {
        archive_read_free(a);
    }
};

using archive_t = unique_ptr<archive*, archive_closer>;

static void extract_zip_files(span<const uint8_t> zip, vector<pair<string, vector<uint8_t>>>& files) {
    struct archive_entry* entry;

    archive_t a{archive_read_new()};

    if (!a)
        throw runtime_error("archive_read_new failed");

    archive_read_support_filter_all(a.get());
    archive_read_support_format_all(a.get());

    auto r = archive_read_open_memory(a.get(), zip.data(), zip.size());

    if (r != ARCHIVE_OK)
        throw runtime_error(archive_error_string(a.get()));

    while (archive_read_next_header(a.get(), &entry) == ARCHIVE_OK) {
        vector<uint8_t> data;

        data.resize(archive_entry_size(entry));

        do {
            const void* buf;
            size_t size;
            la_int64_t offset;

            auto r = archive_read_data_block(a.get(), &buf, &size, &offset);

            if (r == ARCHIVE_EOF)
                break;

            if (r != ARCHIVE_OK)
                throw runtime_error(archive_error_string(a.get()));

            if (size == 0)
                break;

            memcpy(data.data() + offset, buf, size);
        } while (true);

        files.emplace_back(archive_entry_pathname(entry), data);
    }
}

static void dump_ssis(string_view db_server, string_view db_username, string_view db_password) {
    vector<project> projs;

    {
        tds::tds tds(db_server, db_username, db_password, "ssisdump", "SSISDB");

        {
            tds::query sq(tds, "SELECT internal.get_encryption_algorithm()");

            if (!sq.fetch_row())
                throw runtime_error("SSISDB.internal.get_encryption_algorithm returned no value.");

            auto s = (string)sq[0];

            if (s != "AES_256")
                throw runtime_error("Unknown encryption algorithm " + s + ".");
        }

        {
            tds::query sq(tds, R"(SELECT projects.project_id,
    object_versions.object_data
FROM catalog.projects
JOIN internal.object_versions ON object_versions.object_id = projects.project_id AND
    object_versions.object_version_lsn = projects.object_version_lsn)");

            while (sq.fetch_row()) {
                projs.emplace_back((int64_t)sq[0], sq[1].val);
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

            extract_zip_files(p.data, p.files);
        }
    }

    tds::tds tds(db_server, db_username, db_password, "ssisdump");

    {
        tds::trans trans(tds);

        tds.run("TRUNCATE TABLE mharmstone.ssis_files");

        for (const auto& p : projs) {
            for (const auto& f: p.files) {
                tds.run("INSERT INTO mharmstone.ssis_files(project, name, data) VALUES(?, ?, ?)", p.id, f.first, f.second);
            }
        }

        trans.commit();
    }
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
