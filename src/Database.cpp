#include "Database.h"

#include <chrono>
#include <sstream>
#include <stdexcept>

namespace area {

Database::Database() {}

Database::~Database() {
    if (conn_) {
        PQfinish(conn_);
    }
}

void Database::connect(const std::string& url, const std::string& postgres_cert_path) {
    char sep = (url.find('?') != std::string::npos) ? '&' : '?';
    std::string conninfo = url + sep +
        "sslmode=verify-full"
        "&sslrootcert=" + postgres_cert_path;

    conn_ = PQconnectdb(conninfo.c_str());
    if (PQstatus(conn_) != CONNECTION_OK) {
        std::string err = PQerrorMessage(conn_);
        PQfinish(conn_);
        conn_ = nullptr;
        throw std::runtime_error("postgres connection failed (check your postgres_url and postgres_cert in config.json)");
    }
}

std::string Database::getSchema() {
    std::lock_guard lk(mu_);
    if (!conn_) throw std::runtime_error("database not connected");

    const char* sql = R"(
        SELECT
            t.table_schema,
            t.table_name,
            c.column_name,
            c.data_type,
            c.is_nullable,
            c.column_default
        FROM information_schema.tables t
        JOIN information_schema.columns c
            ON t.table_name = c.table_name
            AND t.table_schema = c.table_schema
        WHERE t.table_schema NOT IN ('pg_catalog', 'information_schema')
            AND t.table_type = 'BASE TABLE'
        ORDER BY t.table_schema, t.table_name, c.ordinal_position
    )";

    PGresult* res = PQexec(conn_, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        std::string err = PQerrorMessage(conn_);
        PQclear(res);
        throw std::runtime_error("schema query failed: " + err);
    }

    std::ostringstream out;
    std::string currentTable;
    int nrows = PQntuples(res);

    for (int i = 0; i < nrows; i++) {
        std::string schema = PQgetvalue(res, i, 0);
        std::string table = PQgetvalue(res, i, 1);
        std::string column = PQgetvalue(res, i, 2);
        std::string dtype = PQgetvalue(res, i, 3);
        std::string nullable = PQgetvalue(res, i, 4);
        std::string defval = PQgetvalue(res, i, 5);

        std::string fullTable = schema + "." + table;
        if (fullTable != currentTable) {
            if (!currentTable.empty()) out << "\n";
            out << "TABLE " << fullTable << ":\n";
            currentTable = fullTable;
        }
        out << "  " << column << " " << dtype;
        if (nullable == "NO") out << " NOT NULL";
        if (!std::string(defval).empty()) out << " DEFAULT " << defval;
        out << "\n";
    }

    PQclear(res);
    return out.str();
}

QueryResult Database::execute(const std::string& sql) {
    std::lock_guard lk(mu_);
    QueryResult result;

    if (!conn_) {
        result.error = "database not connected";
        return result;
    }

    auto start = std::chrono::high_resolution_clock::now();
    PGresult* res = PQexec(conn_, sql.c_str());
    auto end = std::chrono::high_resolution_clock::now();

    result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();

    ExecStatusType status = PQresultStatus(res);
    if (status != PGRES_TUPLES_OK && status != PGRES_COMMAND_OK) {
        result.error = PQerrorMessage(conn_);
        PQclear(res);
        return result;
    }

    if (status == PGRES_COMMAND_OK) {
        // Non-SELECT (INSERT, UPDATE, etc.)
        std::string affected = PQcmdTuples(res);
        result.columns = {"affected_rows"};
        result.rows = {{affected}};
        PQclear(res);
        return result;
    }

    int ncols = PQnfields(res);
    int nrows = PQntuples(res);

    for (int c = 0; c < ncols; c++) {
        result.columns.push_back(PQfname(res, c));
    }

    for (int r = 0; r < nrows; r++) {
        std::vector<std::string> row;
        for (int c = 0; c < ncols; c++) {
            if (PQgetisnull(res, r, c)) {
                row.push_back("NULL");
            } else {
                row.push_back(PQgetvalue(res, r, c));
            }
        }
        result.rows.push_back(std::move(row));
    }

    PQclear(res);
    return result;
}

QueryResult Database::executeParams(const std::string& sql, const std::vector<std::string>& params) {
    std::lock_guard lk(mu_);
    QueryResult result;

    if (!conn_) {
        result.error = "database not connected";
        return result;
    }

    std::vector<const char*> values;
    values.reserve(params.size());
    for (auto& p : params) {
        values.push_back(p.c_str());
    }

    auto start = std::chrono::high_resolution_clock::now();
    PGresult* res = PQexecParams(conn_, sql.c_str(),
                                  static_cast<int>(params.size()),
                                  nullptr,      // let PG infer param types
                                  values.data(),
                                  nullptr,      // text format, null-terminated
                                  nullptr,      // all text format
                                  0);           // text result format
    auto end = std::chrono::high_resolution_clock::now();

    result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();

    ExecStatusType status = PQresultStatus(res);
    if (status != PGRES_TUPLES_OK && status != PGRES_COMMAND_OK) {
        result.error = PQerrorMessage(conn_);
        PQclear(res);
        return result;
    }

    if (status == PGRES_COMMAND_OK) {
        std::string affected = PQcmdTuples(res);
        result.columns = {"affected_rows"};
        result.rows = {{affected}};
        PQclear(res);
        return result;
    }

    int ncols = PQnfields(res);
    int nrows = PQntuples(res);

    for (int c = 0; c < ncols; c++) {
        result.columns.push_back(PQfname(res, c));
    }

    for (int r = 0; r < nrows; r++) {
        std::vector<std::string> row;
        for (int c = 0; c < ncols; c++) {
            if (PQgetisnull(res, r, c)) {
                row.push_back("NULL");
            } else {
                row.push_back(PQgetvalue(res, r, c));
            }
        }
        result.rows.push_back(std::move(row));
    }

    PQclear(res);
    return result;
}

} // namespace area
