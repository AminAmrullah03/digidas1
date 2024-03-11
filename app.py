from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from pymongo import MongoClient
import os
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv
from os.path import join, dirname
from bson import ObjectId, json_util
import jwt
import hashlib
from datetime import datetime, timedelta
import json
from werkzeug.security import check_password_hash, generate_password_hash

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME = os.environ.get("DB_NAME")

client = MongoClient(MONGODB_URI)
db = client[DB_NAME]
pindahan = db['pindahan']
pelanggarans = db['pelanggarans']
datasantri = db['datasantri']
datainv = db['datainv']
datapulang = db['pulang']
dataizin = db['izin']
targets = db['target']
datakelas = db['kelas']
pengumumans = db['pengumuman']
ramadan = db['ramadan']

app = Flask(__name__)
app.secret_key = 'hello_print'

TOKEN_KEY = 'mytoken'
SECRET_KEY = 'SPARTA'

app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

jwt = JWTManager(app)

@app.route('/')
def home():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        nis = request.form.get('nis')
        password = request.form.get('password')
        pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        user = datasantri.find_one({"nis": nis})
        if user and (user["password"] == pw_hash):
            session.permanent = True
            session["user_id"] = str(user["_id"])
            return jsonify({
                'result': 'success',
                'user_id': session['user_id'],
                'nama': user['nama']
            })
        else:
            flash("NIS atau password tidak valid.", "danger")
            return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    
    user = datasantri.find_one({"_id": user_id})
    return render_template("dashboard.html", user=user)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/pendataan")
def pendataan():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    return render_template("pendataan_santri.html")

@app.route("/absensi")
def absensi():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    
    return render_template("absensi.html")

@app.route("/tambah_absensi", methods=["POST"])
def tambah_absensi():
    if request.method == 'POST':
            data = {
                'nama': request.form['nama'],
                'waktu': request.form['waktu'],
                'hadir': request.form['hadir'],
                'tanggal' : request.form['tanggal']
            }
            print(data)
            ramadan.insert_one(data)
            return redirect(url_for('absensi_kehadiran', success=1))
    return render_template('absensi_kehadiran')

@app.route("/data_kehadiran")
def data_hadir():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    return render_template("data_kehadiran.html")

@app.route("/absensi_kehadiran")
def absensi_kehadiran():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    return render_template("absensi_kehadiran.html")

@app.route("/profile")
def profile():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    
    user_data = datasantri.find_one({"_id": ObjectId(user_id)})
    nis = user_data['nis']
    pelanggaran = pelanggarans.find({'nis': nis})
    
    if user_data:
        return render_template("profile.html", user=user_data, pelanggaran=pelanggaran)
    else:
        flash("Data santri tidak ditemukan.", "danger")
        return redirect(url_for("home"))

@app.route('/change_password', methods=['POST'])
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))

    raw_new = request.form['current_password'].strip()
    current_password = hashlib.sha256(raw_new.encode()).hexdigest()
    new_password = request.form['new_password'].strip()
    confirm_password = request.form['confirm_password'].strip()

    user = datasantri.find_one({'_id': ObjectId(user_id)})
    
    # Debugging prints
    print('Kata Sandi Saat Ini:', current_password)
    print('Kata Sandi Terenkripsi di Database:', user['password'])
    if current_password != user['password']:
        flash('Kata sandi saat ini tidak benar', 'danger')
        print('password tidak cocok')
        return redirect(url_for('profile'))

    if current_password == user['password']:
        if new_password != confirm_password:
            print('tak cocok')
            flash('Kata sandi baru dan konfirmasi kata sandi tidak cocok', 'danger')
            return redirect(url_for('profile'))
        
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        datasantri.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': hashed_password}})
        flash('Kata sandi berhasil diubah!', 'success')
        print('sandi :', new_password )
        print('Kata sandi berhasil diubah menjadi :', hashed_password)
        return redirect(url_for('profile'))
    
    return render_template('profile')

@app.route('/tambah_santri', methods=['GET', 'POST'])
def tambah_santri():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    if request.method == 'POST':
        nama = request.form['nama']
        nis = request.form['nis']
        jenis_kelamin = request.form['jenis_kelamin']
        no_hp = request.form['no_hp']
        alamat = request.form['alamat']
        raw_password = request.form['password']
        hashed_password = hashlib.sha256(raw_password.encode()).hexdigest()
        data = {
            'nama': nama,
            'nis': nis,
            'jenis_kelamin': jenis_kelamin,
            'no_hp': no_hp,
            'alamat': alamat,
            'password': hashed_password,
            'status': 'santri',
        }
        datasantri.insert_one(data)
        flash('Data berhasil ditambahkan!', 'success')
        return redirect(url_for('tambah_santri', success=1))

    return render_template('tambah_santri.html')

@app.route("/inventaris", methods=['GET', 'POST'])
def inventaris():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    data = list(datainv.find())
    return render_template('inventaris.html', data=data)

@app.route("/pelanggaran")
def pelanggaran():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    
    return render_template("pelanggaran.html")

@app.route('/data_santri', methods=['GET', 'POST'])
def data_santri():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    data = datasantri.find()
    return render_template('data_santri.html', data=data)

@app.route('/hapus_data/<id>')
def hapus_data(id):
    datasantri.delete_one({'_id': ObjectId(id)})
    return redirect(url_for('data_santri'))

@app.route('/get_data_santri/<id>')
def get_data_santri(id):
    data = datasantri.find_one({'_id': ObjectId(id)})
    data['_id'] = str(data['_id'])
    return jsonify(json.loads(json_util.dumps(data)))

@app.route('/edit_data_santri/<id>', methods=['POST'])
def edit_data_santri(id):
    if request.method == 'POST':
        filter_query = {'_id': ObjectId(id)}
        update_data = {
            '$set': {
                'nama': request.form['nama'],
                'nis': request.form['nis'],
                'jenis_kelamin': request.form['jenis_kelamin'],
                'no_hp': request.form['no_hp'],
                'alamat': request.form['alamat'],
            }
        }
        datasantri.update_one(filter_query, update_data)
        return jsonify({'result': 'success'})

@app.route('/tambah_data', methods=['POST'])
def tambah_data():
    if request.method == 'POST':
        data = {
            'nama': request.form['nama'],
            'nis': request.form['nis'],
            'jenis_pelanggaran': request.form['jenis_pelanggaran'],
            'kategori_pelanggaran': request.form['kategori_pelanggaran'],
            'tanggal': request.form['tanggal'],
        }
        pelanggarans.insert_one(data)
        return redirect(url_for('pelanggaran', success=1))

@app.route('/data_pelanggaran', methods=['GET', 'POST'])
def data_pelanggaran():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    data = pelanggarans.find()
    return render_template('data_pelanggaran.html', data=data)

@app.route('/hapus_pelanggaran/<id>')
def hapus_pelanggaran(id):
    pelanggarans.delete_one({'_id': ObjectId(id)})
    return redirect(url_for('data_pelanggaran'))

@app.route('/get_data_pelanggaran/<id>')
def get_data_pelanggaran(id):
    data = pelanggarans.find_one({'_id': ObjectId(id)})
    data['_id'] = str(data['_id'])
    return jsonify(json.loads(json_util.dumps(data)))

@app.route('/edit_data_pelanggaran/<id>', methods=['POST'])
def edit_data_pelanggaran(id):
    if request.method == 'POST':
        filter_query = {'_id': ObjectId(id)}
        update_data = {
            '$set': {
                'nama': request.form['nama'],
                'nis': request.form['nis'],
                'jenis_pelanggaran': request.form['jenis_pelanggaran'],
                'kategori_pelanggaran': request.form['kategori_pelanggaran'],
                'tanggal': request.form['tanggal'],
            }
        }
        pelanggarans.update_one(filter_query, update_data)
        return jsonify({'result': 'success'})

@app.route('/tambah_daftar', methods=['GET', 'POST'])
def tambah_daftar():
    if request.method == 'POST':
        data = {
            'nama_barang': request.form['nama_barang'],
            'jumlah': request.form['jumlah'],
            'kondisi_bagus': request.form['kondisi_bagus'],
            'kondisi_rusak': request.form['kondisi_rusak'],
        }
        datainv.insert_one(data)
        return redirect(url_for('inventaris', success=1))

@app.route('/hapus_data_inventaris/<id>')
def hapus_data_inventaris(id):
    datainv.delete_one({'_id': ObjectId(id)})
    return jsonify({'result': 'success'})

@app.route('/get_data_inventaris/<id>')
def get_data_inventaris(id):
    data = datainv.find_one({'_id': ObjectId(id)})
    data['_id'] = str(data['_id'])
    return jsonify(json.loads(json_util.dumps(data)))

@app.route('/edit_data_inventaris/<id>', methods=['POST'])
def edit_data_inventaris(id):
    if request.method == 'POST':
        filter_query = {'_id': ObjectId(id)}
        update_data = {
            '$set': {
                'nama_barang': request.form['nama_barang'],
                'jumlah': request.form['jumlah'],
                'kondisi_bagus': request.form['kondisi_bagus'],
                'kondisi_rusak': request.form['kondisi_rusak'],
            }
        }

        datainv.update_one(filter_query, update_data)
        return jsonify({'result': 'success'})

@app.route('/mutasi', methods=['GET', 'POST'])
def mutasi():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    data = pindahan.find()
    return render_template('mutasi.html', data=data)

@app.route('/hapus_mutasi/<id>')
def hapus_mutasi(id):
    pindahan.delete_one({'_id': ObjectId(id)})
    return redirect(url_for('mutasi'))

@app.route('/tambah_mutasi', methods=['POST'])
def tambah_mutasi():
    if request.method == 'POST':
        data = {
            'nama': request.form['nama'],
            'jenis_kelamin': request.form['jenis_kelamin'],
            'tanggal': request.form['tanggal'],
            'status': request.form['status'],
        }
        pindahan.insert_one(data)
        return redirect(url_for('mutasi', success=1))

@app.route('/get_mutasi/<id>')
def get_mutasi(id):
    data = pindahan.find_one({'_id': ObjectId(id)})
    data['_id'] = str(data['_id'])
    return jsonify(json.loads(json_util.dumps(data)))

@app.route('/edit_mutasi/<id>', methods=['POST'])
def edit_mutasi(id):
    if request.method == 'POST':
        filter_query = {'_id': ObjectId(id)}
        update_data = {
            '$set': {
                'nama': request.form['nama'],
                'jenis_kelamin': request.form['jenis_kelamin'],
                'tanggal': request.form['tanggal'],
                'status': request.form['status'],
            }
        }
        pindahan.update_one(filter_query, update_data)
        return jsonify({'result': 'success'})

@app.route('/santri_pulang')
def santri_pulang():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    return render_template('santri_pulang.html')

@app.route('/data_pulang', methods=['GET', 'POST'])
def data_pulang():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    data = datapulang.find()
    return render_template('data_pulang.html', data=data)

@app.route('/tambah_pulang', methods=['POST'])
def tambah_pulang():
    if request.method == 'POST':
        data = {
            'nama': request.form['nama'],
            'nis': request.form['nis'],
            'alasan': request.form['alasan'],
            'durasi': request.form['durasi'],
            'tanggal': request.form['tanggal'],
            'penjemput': request.form['penjemput'],
            'status_penjemput': request.form['status_penjemput'],
            'pemberi_izin': request.form['pemberi_izin'],
        }
        datapulang.insert_one(data)
        return redirect(url_for('santri_pulang', success=1))

@app.route('/hapus_pulang/<id>')
def hapus_pulang(id):
    datapulang.delete_one({'_id': ObjectId(id)})
    return redirect(url_for('data_pulang'))

@app.route('/get_data_pulang/<id>')
def get_data_pulang(id):
    data = datapulang.find_one({'_id': ObjectId(id)})
    data['_id'] = str(data['_id'])
    return jsonify(json.loads(json_util.dumps(data)))

@app.route('/edit_data_pulang/<id>', methods=['POST'])
def edit_data_pulang(id):
    if request.method == 'POST':
        filter_query = {'_id': ObjectId(id)}
        update_data = {
            '$set': {
                'nama': request.form['nama'],
                'nis': request.form['nis'],
                'alasan': request.form['alasan'],
                'durasi': request.form['durasi'],
                'tanggal': request.form['tanggal'],
                'penjemput': request.form['penjemput'],
                'status_penjemput': request.form['status_penjemput'],
                'pemberi_izin': request.form['pemberi_izin'],
            }
        }
        datapulang.update_one(filter_query, update_data)
        return jsonify({'result': 'success'})

@app.route('/pengumuman')   
def pengumuman():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    user = datasantri.find_one({"_id": ObjectId(user_id)})
    data = pengumumans.find()
    return render_template('/pengumuman.html', data=data, user=user)

@app.route('/tambah_pengumuman', methods=['GET', 'POST'])
def tambah_pengumuman():
    if request.method == 'POST':
        data = {
            'judul': request.form['judul'],
            'isi': request.form['isi'],
        }
        pengumumans.insert_one(data)
        return redirect(url_for('pengumuman', success=1))

@app.route('/edit_pengumuman', methods=['POST'])
def edit_pengumuman():
    if request.method == 'POST':
        pengumuman_id = request.form['pengumuman_id']
        if ObjectId.is_valid(pengumuman_id):
            updated_data = {
                'judul': request.form['judul'],
                'isi': request.form['isi'],
            }
            pengumumans.update_one({'_id': ObjectId(pengumuman_id)}, {'$set': updated_data})
            return redirect(url_for('pengumuman'))
        else:
            flash('Invalid ObjectId', 'error')
            return redirect(url_for('pengumuman'))

@app.route('/delete_pengumuman/<pengumuman_id>', methods=['DELETE'])
def delete_pengumuman(pengumuman_id):
    try:
        pengumuman_id_obj = ObjectId(pengumuman_id)
        result = pengumumans.delete_one({'_id': pengumuman_id_obj})

        if result.deleted_count > 0:
            return '', 204 
        else:
            return 'Pengumuman tidak ditemukan', 404

    except Exception as e:
        print('Error during deletion:', str(e))
        return 'Internal Server Error', 500

@app.route('/izin_keluar')
def izin_keluar():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    return render_template('izin_keluar.html')

@app.route('/data_izin', methods=['GET', 'POST'])
def data_izin():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    data = dataizin.find()
    return render_template('data_izin.html', data=data)

@app.route('/get_data_izin/<id>')
def get_data_izin(id):
    data = dataizin.find_one({'_id': ObjectId(id)})
    data['_id'] = str(data['_id'])
    return jsonify(json.loads(json_util.dumps(data)))

@app.route('/edit_data_izin/<id>', methods=['POST'])
def edit_data_izin(id):
    if request.method == 'POST':
        filter_query = {'_id': ObjectId(id)}
        update_data = {
            '$set': {
                'nama': request.form['nama'],
                'nis': request.form['nis'],
                'alasan': request.form['alasan'],
                'tanggal': request.form['tanggal'],
            }
        }
        dataizin.update_one(filter_query, update_data)
        return jsonify({'result': 'success'})

@app.route('/tambah_keluar', methods=['POST'])
def tambah_keluar():
    if request.method == 'POST':
        data = {
            'nama': request.form['nama'],
            'nis': request.form['nis'],
            'alasan': request.form['alasan'],
            'durasi': request.form['durasi'],
            'tanggal': request.form['tanggal'],
        }
        dataizin.insert_one(data)
        return redirect(url_for('izin_keluar', success=1))

@app.route('/hapus_izin/<id>')
def hapus_izin(id):
    dataizin.delete_one({'_id': ObjectId(id)})
    return redirect(url_for('data_izin'))

@app.route('/target')
def target():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    data = targets.find()
    user = datasantri.find_one({"_id": ObjectId(user_id)})
    return render_template('target.html', data=data, user=user)

@app.route('/tambah_target', methods=['GET', 'POST'])
def tambah_target():
    if request.method == 'POST':
        data = {
            'judul': request.form['judul'],
            'isi': request.form['isi'],
        }
        targets.insert_one(data)
        return redirect(url_for('target', success=1))
    
@app.route('/edit_target', methods=['POST'])
def edit_target():
    if request.method == 'POST':
        target_id = request.form['target_id']
        if ObjectId.is_valid(target_id):
            updated_data = {
                'judul': request.form['judul'],
                'isi': request.form['isi'],
            }
            targets.update_one({'_id': ObjectId(target_id)}, {'$set': updated_data})
            return redirect(url_for('target'))
        else:
            flash('Invalid ObjectId', 'error')
            return redirect(url_for('target'))

@app.route('/delete_target/<target_id>', methods=['DELETE'])
def delete_target(target_id):
    try:
        target_id_obj = ObjectId(target_id)
        result = targets.delete_one({'_id': target_id_obj})

        if result.deleted_count > 0:
            return '', 204 
        else:
            return 'Target not found', 404

    except Exception as e:
        print('Error during deletion:', str(e))
        return 'Internal Server Error', 500

@app.route('/jurnal', methods=['GET', 'POST'])
def jurnal():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    data = datakelas.find()
    return render_template('jurnal.html', data=data)

@app.route('/get_data_kelas/<id>')
def get_data_kelas(id):
    data = datakelas.find_one({'_id': ObjectId(id)})
    if data:
        data['_id'] = str(data['_id'])
        return jsonify(json.loads(json_util.dumps(data)))
    else:
        return jsonify({'error': 'Data not found'})

@app.route('/hapus_kelas/<id>')
def hapus_kelas(id):
    datakelas.delete_one({'_id': ObjectId(id)})
    return jsonify({'result': 'success'})

@app.route('/edit_kelas/<id>', methods=['POST'])
def edit_kelas(id):
    if request.method == 'POST':
        filter_query = {'_id': ObjectId(id)}
        update_data = {
            '$set': {
                'nama_kelas': request.form['nama_kelas'],
            }
        }
        datakelas.update_one(filter_query, update_data)
        return jsonify({'result': 'success'})

@app.route('/tambah_kelas', methods=['GET', 'POST'])
def tambah_kelas():
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    if request.method == 'POST':
        nama_kelas = request.form['nama_kelas']
        datakelas.insert_one({'nama_kelas': nama_kelas, 'santri': []})

        flash('Kelas berhasil ditambahkan', 'success')
        return redirect(url_for('jurnal'))

    return render_template('tambah_kelas.html')

@app.route('/kelas/<kelas_id>', methods=['GET', 'POST'])
def kelas(kelas_id):
    user_id = session.get("user_id")
    if not user_id:
        flash("Anda harus login terlebih dahulu!", "danger")
        return redirect(url_for("login"))
    santri_index = -1  # Initialize santri_index with a default value

    if not ObjectId.is_valid(kelas_id):
        flash('Invalid ObjectId for kelas_id', 'error')
        return redirect(url_for('jurnal'))

    kelas = datakelas.find_one({'_id': ObjectId(kelas_id)})

    if not kelas:
        flash('Kelas not found', 'error')
        return redirect(url_for('jurnal'))

    if request.method == 'POST':
        nama_santri = request.form['nama_santri']
        nis_santri = request.form['nis_santri']

        # Get the loop index from the form data
        santri_index = int(request.form.get('santri_index', -1))

        datakelas.update_one(
            {'_id': ObjectId(kelas_id)},
            {'$addToSet': {'santri': {'nama': nama_santri, 'nis': nis_santri}}}
        )
        flash('Santri berhasil ditambahkan ke kelas', 'success')
        kelas = datakelas.find_one({'_id': ObjectId(kelas_id)})

    return render_template('kelas.html', kelas=kelas, santri_index=santri_index)

@app.route('/update_santri/<kelas_id>', methods=['POST'])
def update_santri(kelas_id):
    try:
        santri_index = int(request.form['edit_santri'])
        nama_santri = request.form['edit_nama_santri']
        nis_santri = request.form['edit_nis_santri']
        datakelas.update_one(
            {'_id': ObjectId(kelas_id)},
            {'$set': {'santri.{0}'.format(santri_index): {'nama': nama_santri, 'nis': nis_santri}}}
        )
        print('Data Santri berhasil diubah')
        return jsonify({'message': 'Data Santri berhasil diubah'})

    except Exception as e:
        print('Error during santri update:', str(e))
        return jsonify({'error': 'Terjadi kesalahan saat mengupdate data santri'}), 500

@app.route('/get_santri/<kelas_id>/<santri_index>', methods=['GET'])
def get_santri(kelas_id, santri_index):
    if not ObjectId.is_valid(kelas_id):
        return jsonify({'message': 'Invalid data'}), 400

    kelas = datakelas.find_one({'_id': ObjectId(kelas_id)})

    if not kelas:
        return jsonify({'message': 'Kelas not found'}), 404

    try:
        santri_index = int(santri_index)
        if santri_index < 0 or santri_index >= len(kelas.get('santri', [])):
            raise ValueError("Invalid santri_index")
    except ValueError:
        return jsonify({'message': 'Invalid santri_index'}), 400

    santri_terpilih = kelas['santri'][santri_index]
    
    return jsonify({
        'nama': santri_terpilih.get('nama', ''),
        'nis': santri_terpilih.get('nis', '')
    })

@app.route('/hapus_santri/<kelas_id>/<santri_index>', methods=['GET','POST'])
def hapus_santri(kelas_id, santri_index):
    if not ObjectId.is_valid(kelas_id):
        return jsonify({'message': 'Invalid data'}), 400

    kelas = datakelas.find_one({'_id': ObjectId(kelas_id)})

    if not kelas:
        return jsonify({'message': 'Kelas not found'}), 404

    try:
        santri_index = int(santri_index)
        if santri_index < 0 or santri_index >= len(kelas.get('santri', [])):
            raise ValueError("Invalid santri_index")
    except ValueError:
        return jsonify({'message': 'Invalid santri_index'}), 400

    del kelas['santri'][santri_index]
    datakelas.update_one({'_id': ObjectId(kelas_id)}, {'$set': {'santri': kelas['santri']}})

    return jsonify({'message': 'Santri berhasil dihapus'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)