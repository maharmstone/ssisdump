#include <vector>
#include <string>
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {
    vector<string> args;
    string db_server;

    args.reserve(argc);

    for (int i = 0; i < argc; i++) {
        args.emplace_back(argv[i]);
    }

    if (argc >= 2)
        db_server = args[1];

    if (db_server.empty()) {
        cout << "Usage: ssisdump <server>" << endl;
        return 1;
    }

    // FIXME

    return 0;
}
