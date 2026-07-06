# SQL injection: a request parameter is interpolated straight into an
# ActiveRecord condition string — CWE-89. A correct scanner fires TAINT-001. The
# safe, parameterized form (a `?` placeholder with the value as a bind arg) lives
# in clean_safe_db.rb and must NOT fire.
class ReportsController
  def by_user
    id = params[:user_id]
    User.where("id = #{id}") # nox-expect: TAINT-001
  end

  def raw_lookup
    name = params[:name]
    User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'") # nox-expect: TAINT-001
  end
end
