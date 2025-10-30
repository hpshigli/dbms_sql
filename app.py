from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_mysqldb import MySQL

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_change_in_production'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'asdf;lkj'
app.config['MYSQL_DB'] = 'attack_surface_intelligence1'

mysql = MySQL(app)

# ============= DASHBOARD =============
@app.route('/')
def index():
    cur = mysql.connection.cursor()
    
    # Get comprehensive statistics
    cur.execute("SELECT COUNT(*) FROM ASSET")
    total_assets = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM VULNERABILITY WHERE severity='Critical'")
    critical_vulns = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM ALERT WHERE severity='Critical'")
    critical_alerts = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM EXPOSURE")
    total_exposures = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM PATCH_DEPLOYMENT WHERE status='Pending'")
    pending_patches = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM INCIDENT WHERE status IN ('Open', 'In Progress')")
    active_incidents = cur.fetchone()[0]
    
    cur.close()
    
    return render_template('dashboard.html', 
                         total_assets=total_assets,
                         critical_vulns=critical_vulns,
                         critical_alerts=critical_alerts,
                         total_exposures=total_exposures,
                         pending_patches=pending_patches,
                         active_incidents=active_incidents)

# ============= CLOUD ACCOUNTS =============
@app.route('/accounts')
def accounts():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT ca.account_id, ca.provider, ca.account_name, ca.created_at,
               COUNT(a.asset_id) as asset_count
        FROM CLOUD_ACCOUNT ca
        LEFT JOIN ASSET a ON ca.account_id = a.account_id
        GROUP BY ca.account_id
    """)
    accounts = cur.fetchall()
    cur.close()
    return render_template('accounts.html', accounts=accounts)

@app.route('/accounts/add', methods=['POST'])
def add_account():
    provider = request.form['provider']
    account_name = request.form['account_name']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO CLOUD_ACCOUNT (provider, account_name)
        VALUES (%s, %s)
    """, (provider, account_name))
    mysql.connection.commit()
    cur.close()
    
    flash('Cloud account added successfully!', 'success')
    return redirect(url_for('accounts'))

@app.route('/accounts/delete/<int:id>')
def delete_account(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM CLOUD_ACCOUNT WHERE account_id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Cloud account deleted successfully!', 'success')
    return redirect(url_for('accounts'))

@app.route('/accounts/update/<int:id>', methods=['POST'])
def update_account(id):
    provider = request.form['provider']
    account_name = request.form['account_name']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE CLOUD_ACCOUNT 
        SET provider=%s, account_name=%s 
        WHERE account_id=%s
    """, (provider, account_name, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Cloud account updated successfully!', 'success')
    return redirect(url_for('accounts'))

# ============= ASSETS CRUD =============
@app.route('/assets')
def assets():
    cur = mysql.connection.cursor()
    search = request.args.get('search', '')
    
    if search:
        cur.execute("""
            SELECT a.asset_id, a.name, a.type, a.ip, ca.provider, ca.account_name
            FROM ASSET a
            JOIN CLOUD_ACCOUNT ca ON a.account_id = ca.account_id
            WHERE a.name LIKE %s OR a.type LIKE %s OR a.ip LIKE %s
        """, (f'%{search}%', f'%{search}%', f'%{search}%'))
    else:
        cur.execute("""
            SELECT a.asset_id, a.name, a.type, a.ip, ca.provider, ca.account_name
            FROM ASSET a
            JOIN CLOUD_ACCOUNT ca ON a.account_id = ca.account_id
        """)
    
    assets = cur.fetchall()
    
    # Get accounts for dropdown
    cur.execute("SELECT account_id, account_name, provider FROM CLOUD_ACCOUNT")
    accounts = cur.fetchall()
    
    cur.close()
    return render_template('assets.html', assets=assets, accounts=accounts)

@app.route('/assets/add', methods=['POST'])
def add_asset():
    name = request.form['name']
    asset_type = request.form['type']
    ip = request.form['ip']
    account_id = request.form['account_id']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO ASSET (name, type, ip, account_id)
        VALUES (%s, %s, %s, %s)
    """, (name, asset_type, ip, account_id))
    mysql.connection.commit()
    cur.close()
    
    flash('Asset added successfully!', 'success')
    return redirect(url_for('assets'))

@app.route('/assets/update/<int:id>', methods=['POST'])
def update_asset(id):
    name = request.form['name']
    asset_type = request.form['type']
    ip = request.form['ip']
    account_id = request.form['account_id']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE ASSET 
        SET name=%s, type=%s, ip=%s, account_id=%s 
        WHERE asset_id=%s
    """, (name, asset_type, ip, account_id, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Asset updated successfully!', 'success')
    return redirect(url_for('assets'))

@app.route('/assets/delete/<int:id>')
def delete_asset(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM ASSET WHERE asset_id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Asset deleted successfully!', 'success')
    return redirect(url_for('assets'))

# ============= EXPOSURES =============
@app.route('/exposures')
def exposures():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT e.exposure_id, a.name AS asset_name, a.ip, e.port, 
               e.service, e.detected_at
        FROM EXPOSURE e
        JOIN ASSET a ON e.asset_id = a.asset_id
        ORDER BY e.detected_at DESC
    """)
    exposures = cur.fetchall()
    
    # Get assets for dropdown
    cur.execute("SELECT asset_id, name FROM ASSET")
    assets = cur.fetchall()
    
    cur.close()
    return render_template('exposures.html', exposures=exposures, assets=assets)

@app.route('/exposures/add', methods=['POST'])
def add_exposure():
    asset_id = request.form['asset_id']
    port = request.form['port']
    service = request.form['service']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO EXPOSURE (asset_id, port, service)
        VALUES (%s, %s, %s)
    """, (asset_id, port, service))
    mysql.connection.commit()
    cur.close()
    
    flash('Exposure added successfully!', 'success')
    return redirect(url_for('exposures'))

@app.route('/exposures/delete/<int:id>')
def delete_exposure(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM EXPOSURE WHERE exposure_id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Exposure deleted successfully!', 'success')
    return redirect(url_for('exposures'))

@app.route('/exposures/update/<int:id>', methods=['POST'])
def update_exposure(id):
    asset_id = request.form['asset_id']
    port = request.form['port']
    service = request.form['service']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE EXPOSURE 
        SET asset_id=%s, port=%s, service=%s 
        WHERE exposure_id=%s
    """, (asset_id, port, service, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Exposure updated successfully!', 'success')
    return redirect(url_for('exposures'))

# ============= VULNERABILITIES CRUD =============
@app.route('/vulnerabilities')
def vulnerabilities():
    cur = mysql.connection.cursor()
    severity_filter = request.args.get('severity', '')
    
    if severity_filter:
        cur.execute("""
            SELECT v.vuln_id, a.name AS asset_name, v.cve_id, v.severity, 
                   v.description, v.discovered_at, v.asset_id
            FROM VULNERABILITY v
            JOIN ASSET a ON v.asset_id = a.asset_id
            WHERE v.severity = %s
            ORDER BY v.discovered_at DESC
        """, (severity_filter,))
    else:
        cur.execute("""
            SELECT v.vuln_id, a.name AS asset_name, v.cve_id, v.severity, 
                   v.description, v.discovered_at, v.asset_id
            FROM VULNERABILITY v
            JOIN ASSET a ON v.asset_id = a.asset_id
            ORDER BY FIELD(v.severity, 'Critical', 'High', 'Medium', 'Low')
        """)
    
    vulns = cur.fetchall()
    
    # Get assets for dropdown
    cur.execute("SELECT asset_id, name FROM ASSET")
    assets = cur.fetchall()
    
    cur.close()
    return render_template('vulnerabilities.html', vulnerabilities=vulns, assets=assets)

@app.route('/vulnerabilities/add', methods=['POST'])
def add_vulnerability():
    asset_id = request.form['asset_id']
    cve_id = request.form['cve_id']
    severity = request.form['severity']
    description = request.form['description']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO VULNERABILITY (asset_id, cve_id, severity, description)
        VALUES (%s, %s, %s, %s)
    """, (asset_id, cve_id, severity, description))
    mysql.connection.commit()
    cur.close()
    
    flash('Vulnerability added successfully!', 'success')
    return redirect(url_for('vulnerabilities'))

@app.route('/vulnerabilities/delete/<int:id>')
def delete_vulnerability(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM VULNERABILITY WHERE vuln_id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Vulnerability deleted successfully!', 'success')
    return redirect(url_for('vulnerabilities'))

@app.route('/vulnerabilities/update/<int:id>', methods=['POST'])
def update_vulnerability(id):
    asset_id = request.form['asset_id']
    cve_id = request.form['cve_id']
    severity = request.form['severity']
    description = request.form['description']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE VULNERABILITY 
        SET asset_id=%s, cve_id=%s, severity=%s, description=%s 
        WHERE vuln_id=%s
    """, (asset_id, cve_id, severity, description, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Vulnerability updated successfully!', 'success')
    return redirect(url_for('vulnerabilities'))

# ============= PATCHES =============
@app.route('/patches')
def patches():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT p.patch_id, v.cve_id, a.name AS asset_name, v.severity,
               p.patch_version, p.release_date
        FROM PATCH p
        JOIN VULNERABILITY v ON p.vuln_id = v.vuln_id
        JOIN ASSET a ON v.asset_id = a.asset_id
        ORDER BY p.release_date DESC
    """)
    patches = cur.fetchall()
    
    # Get vulnerabilities for dropdown
    cur.execute("SELECT vuln_id, cve_id FROM VULNERABILITY")
    vulnerabilities = cur.fetchall()
    
    cur.close()
    return render_template('patches.html', patches=patches, vulnerabilities=vulnerabilities)

@app.route('/patches/add', methods=['POST'])
def add_patch():
    vuln_id = request.form['vuln_id']
    patch_version = request.form['patch_version']
    release_date = request.form['release_date']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO PATCH (vuln_id, patch_version, release_date)
        VALUES (%s, %s, %s)
    """, (vuln_id, patch_version, release_date))
    mysql.connection.commit()
    cur.close()
    
    flash('Patch added successfully!', 'success')
    return redirect(url_for('patches'))

@app.route('/patches/delete/<int:id>')
def delete_patch(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM PATCH WHERE patch_id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Patch deleted successfully!', 'success')
    return redirect(url_for('patches'))

@app.route('/patches/update/<int:id>', methods=['POST'])
def update_patch(id):
    vuln_id = request.form['vuln_id']
    patch_version = request.form['patch_version']
    release_date = request.form['release_date']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE PATCH 
        SET vuln_id=%s, patch_version=%s, release_date=%s 
        WHERE patch_id=%s
    """, (vuln_id, patch_version, release_date, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Patch updated successfully!', 'success')
    return redirect(url_for('patches'))

# ============= PATCH DEPLOYMENTS =============
@app.route('/deployments')
def deployments():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT pd.deploy_id, a.name AS asset_name, pd.status, pd.deployed_at
        FROM PATCH_DEPLOYMENT pd
        JOIN ASSET a ON pd.asset_id = a.asset_id
        ORDER BY pd.deployed_at DESC
    """)
    deployments = cur.fetchall()
    
    # Get assets for dropdown
    cur.execute("SELECT asset_id, name FROM ASSET")
    assets = cur.fetchall()
    
    cur.close()
    return render_template('deployments.html', deployments=deployments, assets=assets)

@app.route('/deployments/add', methods=['POST'])
def add_deployment():
    asset_id = request.form['asset_id']
    status = request.form['status']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO PATCH_DEPLOYMENT (asset_id, status)
        VALUES (%s, %s)
    """, (asset_id, status))
    mysql.connection.commit()
    cur.close()
    
    flash('Deployment added successfully!', 'success')
    return redirect(url_for('deployments'))

@app.route('/deployments/update/<int:id>', methods=['POST'])
def update_deployment(id):
    status = request.form['status']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE PATCH_DEPLOYMENT SET status=%s WHERE deploy_id=%s
    """, (status, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Deployment status updated!', 'success')
    return redirect(url_for('deployments'))

@app.route('/deployments/delete/<int:id>')
def delete_deployment(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM PATCH_DEPLOYMENT WHERE deploy_id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Deployment deleted successfully!', 'success')
    return redirect(url_for('deployments'))

# ============= ALERTS CRUD =============
@app.route('/alerts')
def alerts():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT al.alert_id, a.name AS asset_name, al.severity, 
               al.description, al.created_at
        FROM ALERT al
        JOIN ASSET a ON al.asset_id = a.asset_id
        ORDER BY al.created_at DESC
    """)
    alerts = cur.fetchall()
    
    cur.execute("SELECT asset_id, name FROM ASSET")
    assets = cur.fetchall()
    
    cur.close()
    return render_template('alerts.html', alerts=alerts, assets=assets)

@app.route('/alerts/add', methods=['POST'])
def add_alert():
    asset_id = request.form['asset_id']
    severity = request.form['severity']
    description = request.form['description']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO ALERT (asset_id, severity, description)
        VALUES (%s, %s, %s)
    """, (asset_id, severity, description))
    mysql.connection.commit()
    cur.close()
    
    flash('Alert created successfully!', 'success')
    return redirect(url_for('alerts'))

@app.route('/alerts/delete/<int:id>')
def delete_alert(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM ALERT WHERE alert_id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Alert deleted successfully!', 'success')
    return redirect(url_for('alerts'))

# ============= INCIDENTS CRUD =============
@app.route('/incidents')
def incidents():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT i.incident_id, a.name AS asset_name, i.classification, 
               i.status, i.opened_at, i.alert_id
        FROM INCIDENT i
        JOIN ALERT al ON i.alert_id = al.alert_id
        JOIN ASSET a ON al.asset_id = a.asset_id
        ORDER BY i.opened_at DESC
    """)
    incidents = cur.fetchall()
    
    cur.execute("SELECT alert_id, description FROM ALERT")
    alerts_list = cur.fetchall()
    
    cur.close()
    return render_template('incidents.html', incidents=incidents, alerts_list=alerts_list)

@app.route('/incidents/add', methods=['POST'])
def add_incident():
    alert_id = request.form['alert_id']
    classification = request.form['classification']
    status = request.form['status']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO INCIDENT (alert_id, classification, status)
        VALUES (%s, %s, %s)
    """, (alert_id, classification, status))
    mysql.connection.commit()
    cur.close()
    
    flash('Incident created successfully!', 'success')
    return redirect(url_for('incidents'))

@app.route('/incidents/update_status/<int:id>', methods=['POST'])
def update_incident_status(id):
    status = request.form['status']
    
    cur = mysql.connection.cursor()
    cur.execute("UPDATE INCIDENT SET status=%s WHERE incident_id=%s", (status, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Incident status updated!', 'success')
    return redirect(url_for('incidents'))

@app.route('/incidents/delete/<int:id>')
def delete_incident(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM INCIDENT WHERE incident_id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Incident deleted successfully!', 'success')
    return redirect(url_for('incidents'))

@app.route('/alerts/update/<int:id>', methods=['POST'])
def update_alert(id):
    asset_id = request.form['asset_id']
    severity = request.form['severity']
    description = request.form['description']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE ALERT 
        SET asset_id=%s, severity=%s, description=%s 
        WHERE alert_id=%s
    """, (asset_id, severity, description, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Alert updated successfully!', 'success')
    return redirect(url_for('alerts'))

@app.route('/incidents/update/<int:id>', methods=['POST'])
def update_incident(id):
    alert_id = request.form['alert_id']
    classification = request.form['classification']
    status = request.form['status']
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE INCIDENT 
        SET alert_id=%s, classification=%s, status=%s 
        WHERE incident_id=%s
    """, (alert_id, classification, status, id))
    mysql.connection.commit()
    cur.close()
    
    flash('Incident updated successfully!', 'success')
    return redirect(url_for('incidents'))

# ============= API ENDPOINTS FOR AJAX =============
@app.route('/api/stats')
def api_stats():
    cur = mysql.connection.cursor()
    
    stats = {}
    cur.execute("SELECT COUNT(*) FROM ASSET")
    stats['total_assets'] = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM VULNERABILITY WHERE severity='Critical'")
    stats['critical_vulns'] = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM ALERT WHERE severity='Critical'")
    stats['critical_alerts'] = cur.fetchone()[0]
    
    cur.close()
    
    return jsonify(stats)

# ============= BULK OPERATIONS =============
@app.route('/assets/bulk_delete', methods=['POST'])
def bulk_delete_assets():
    asset_ids = request.form.getlist('asset_ids[]')
    
    if asset_ids:
        cur = mysql.connection.cursor()
        for asset_id in asset_ids:
            cur.execute("DELETE FROM ASSET WHERE asset_id=%s", (asset_id,))
        mysql.connection.commit()
        cur.close()
        
        flash(f'{len(asset_ids)} assets deleted successfully!', 'success')
    
    return redirect(url_for('assets'))

if __name__ == '__main__':
    app.run(debug=True)
