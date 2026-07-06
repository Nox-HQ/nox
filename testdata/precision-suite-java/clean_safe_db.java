// Safe database access in Java — a PreparedStatement with a ? placeholder binds
// the untrusted value via setString rather than concatenating it into the SQL
// string, so no injection is possible. Zero findings expected.
package com.example.store;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

public class SafeUserStore {

    // lookupUser uses a parameterized query: the driver binds `id` to the ?
    // placeholder, so the value can never alter the query structure.
    public ResultSet lookupUser(HttpServletRequest request, Connection conn) throws SQLException {
        String id = request.getParameter("id");
        PreparedStatement ps = conn.prepareStatement("SELECT name, email FROM users WHERE id = ?");
        ps.setString(1, id);
        return ps.executeQuery();
    }
}
