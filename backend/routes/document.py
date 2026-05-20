import os
import uuid
from io import BytesIO
from flask import Blueprint, request, jsonify, send_file, current_app, g
from werkzeug.utils import secure_filename
from extensions import db
from models.document import Document
from models.user import User  
from middleware.jwt_auth import jwt_required, role_required
from services.encryption import encrypt_and_save, load_and_decrypt
from services.signature import compute_sha256, sign_document, verify_signature, verify_integrity

document_bp = Blueprint("document", __name__, url_prefix="/api/documents")

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "docx"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@document_bp.route("/upload", methods=["POST"])
@jwt_required
@role_required("user", "manager", "admin")
def upload_document():
    current_user = User.query.get(g.current_user_id)

    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    file_bytes = file.read()
    file_size = len(file_bytes)

    if file_size > MAX_FILE_SIZE:
        return jsonify({"error": "File size exceeds the 10MB limit"}), 400

    original_filename = secure_filename(file.filename)
    file_extension = os.path.splitext(original_filename)[1].lower()
    stored_filename = str(uuid.uuid4()) + ".enc"
    
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    save_path = os.path.join(upload_folder, stored_filename)

    file_hash = compute_sha256(file_bytes)

    signature = None
    if getattr(current_user, 'private_key_pem', None):
        try:
            signature = sign_document(file_bytes, current_user.private_key_pem)
        except Exception as e:
            return jsonify({"error": f"Failed to sign document: {str(e)}"}), 500

    try:
        encrypt_and_save(file_bytes, save_path)
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

    new_doc = Document(
        user_id=current_user.id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_size=file_size,
        file_type=file.content_type or "application/octet-stream",
        file_extension=file_extension,
        is_encrypted=True,
        sha256_hash=file_hash,
        digital_signature=signature,
        description=request.form.get("description", "")
    )
    
    db.session.add(new_doc)
    db.session.commit()

    return jsonify({"message": "File uploaded and encrypted securely", "document": new_doc.to_dict()}), 201


@document_bp.route("/<int:doc_id>/download", methods=["GET"])
@jwt_required
def download_document(doc_id):
    current_user = User.query.get(g.current_user_id)
    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != current_user.id and g.current_role not in ["manager", "admin"]:
        return jsonify({"error": "Unauthorized access to this document"}), 403

    upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
    file_path = os.path.join(upload_folder, doc.stored_filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found on server"}), 404

    try:
        decrypted_bytes = load_and_decrypt(file_path)
    except Exception as e:
        return jsonify({"error": f"Decryption failed. File may be tampered! Details: {str(e)}"}), 500

    return send_file(
        BytesIO(decrypted_bytes),
        as_attachment=True,
        download_name=doc.original_filename,
        mimetype=doc.file_type
    )


@document_bp.route("/<int:doc_id>/verify", methods=["GET"])
@jwt_required
def verify_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    file_owner = User.query.get(doc.user_id)

    upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
    file_path = os.path.join(upload_folder, doc.stored_filename)

    try:
        decrypted_bytes = load_and_decrypt(file_path)
    except Exception:
        return jsonify({
            "document_id": doc.id,
            "filename": doc.original_filename,
            "is_intact": False,
            "is_authentic": False,
            "stored_hash": doc.sha256_hash,
            "current_hash": "ERROR_DECRYPTION_FAILED",
            "message": "File encryption is broken or tampered."
        }), 400

    # Compute the current hash of the decrypted file to send to the frontend
    current_hash = compute_sha256(decrypted_bytes)
    
    # Compare the hashes
    is_intact = (current_hash == doc.sha256_hash)
    
    # Verify signature (if no signature exists, return None instead of False)
    is_authentic = None 
    if doc.digital_signature and getattr(file_owner, 'public_key_pem', None):
        is_authentic = verify_signature(decrypted_bytes, doc.digital_signature, file_owner.public_key_pem)

    return jsonify({
        "document_id": doc.id,
        "filename": doc.original_filename,
        "is_intact": is_intact,
        "is_authentic": is_authentic,
        "stored_hash": doc.sha256_hash,
        "current_hash": current_hash,
        "message": "Verification complete" if is_intact else "Verification failed! File may be tampered."
    }), 200


@document_bp.route("/", methods=["GET"])
@jwt_required
def get_my_documents():
    docs = Document.query.filter_by(user_id=g.current_user_id).all()
    return jsonify({"documents": [doc.to_dict() for doc in docs]}), 200


@document_bp.route("/<int:doc_id>", methods=["DELETE"])
@jwt_required
def delete_document(doc_id):
    current_user = User.query.get(g.current_user_id)
    doc = Document.query.get_or_404(doc_id)

    # Check permissions (Owner or Admin)
    if doc.user_id != current_user.id and g.current_role != "admin":
        return jsonify({"error": "Unauthorized to delete this document"}), 403

    upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
    file_path = os.path.join(upload_folder, doc.stored_filename)

    # Remove the physical encrypted file from the server
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            return jsonify({"error": f"Failed to delete physical file: {str(e)}"}), 500

    # Remove the record from the database
    db.session.delete(doc)
    db.session.commit()

    return jsonify({"message": "Document deleted successfully"}), 200