#include <vector>
#include <string>
#include <iostream>
#include <span>
#include <tdscpp.h>

using namespace std;

struct project {
    project(int64_t id, string_view name, span<const uint8_t> enc) : id(id), name(name) {
        this->enc.assign(enc.begin(), enc.end());
    }

    int64_t id;
    string name;
    vector<uint8_t> enc;
};

static void dump_ssis(string_view db_server, string_view db_username, string_view db_password) {
    vector<project> projs;

    tds::tds tds(db_server, db_username, db_password, "ssisdump", "SSISDB");

    // FIXME - get internal.get_encryption_algorithm value

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
        tds.run(tds::no_check{"OPEN SYMMETRIC KEY MS_Enckey_Proj_" + to_string(p.id) + " DECRYPTION BY CERTIFICATE MS_Cert_Proj_" + to_string(p.id)});

        // FIXME - get key and IV from internal.catalog_encryption_keys

        tds.run(tds::no_check{"CLOSE SYMMETRIC KEY MS_Enckey_Proj_" + to_string(p.id)});
    }

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
