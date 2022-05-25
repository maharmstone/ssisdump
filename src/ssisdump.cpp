#include <vector>
#include <string>
#include <iostream>
#include <tdscpp.h>

using namespace std;

static void dump_ssis(const string& db_server, string_view db_username, string_view db_password) {
    tds::tds tds(db_server, db_username, db_password, "ssisdump");

    // FIXME
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
