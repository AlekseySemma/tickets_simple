from fastapi import UploadFile


class CommentService:
    def __init__(
        self,
        *,
        normalize_optional_uploaded_files,
        detect_comment_media_kind,
        make_safe_upload_name,
        build_comment_media_object_key,
        store_upload_file_to_storage_async,
        delete_stored_file,
        add_ticket_log,
        log_action_file_added: str,
        attachment_model,
        comment_model,
        comment_media_model,
        comment_out_model,
        comment_media_out_model,
        comment_media_extensions,
        http_exception_cls,
    ):
        self.normalize_optional_uploaded_files = normalize_optional_uploaded_files
        self.detect_comment_media_kind = detect_comment_media_kind
        self.make_safe_upload_name = make_safe_upload_name
        self.build_comment_media_object_key = build_comment_media_object_key
        self.store_upload_file_to_storage_async = store_upload_file_to_storage_async
        self.delete_stored_file = delete_stored_file
        self.add_ticket_log = add_ticket_log
        self.log_action_file_added = log_action_file_added
        self.attachment_model = attachment_model
        self.comment_model = comment_model
        self.comment_media_model = comment_media_model
        self.comment_out_model = comment_out_model
        self.comment_media_out_model = comment_media_out_model
        self.comment_media_extensions = set(comment_media_extensions)
        self.http_exception_cls = http_exception_cls

    def create_ticket_attachment_record(
        self,
        *,
        db,
        ticket_id: int,
        uploader_id: int,
        upload: UploadFile,
        stored_path: str,
        file_hash: str,
        file_size: int,
    ):
        attachment = self.attachment_model(
            ticket_id=ticket_id,
            uploader_id=uploader_id,
            file_path=stored_path,
            original_name=upload.filename,
        )
        attachment.file_sha256 = file_hash
        attachment.file_size_bytes = file_size
        db.add(attachment)
        self.add_ticket_log(db, ticket_id=ticket_id, actor_id=uploader_id, action=self.log_action_file_added)
        return attachment

    def create_comment_media_record(
        self,
        *,
        db,
        comment_id: int,
        upload: UploadFile,
        stored_path: str,
        file_hash: str,
        file_size: int,
        media_kind: str,
    ):
        item = self.comment_media_model(
            comment_id=comment_id,
            file_path=stored_path,
            original_name=upload.filename,
            media_kind=media_kind,
        )
        item.file_sha256 = file_hash
        item.file_size_bytes = file_size
        db.add(item)
        return item

    def serialize_comment_out(self, comment, media_items=None):
        return self.comment_out_model(
            id=comment.id,
            ticket_id=comment.ticket_id,
            author_id=comment.author_id,
            text=comment.text,
            created_at=comment.created_at,
            media=[
                self.comment_media_out_model(
                    id=item.id,
                    comment_id=item.comment_id,
                    file_path=item.file_path,
                    original_name=item.original_name,
                    media_kind=item.media_kind,
                    file_size_bytes=item.file_size_bytes,
                    file_sha256=item.file_sha256,
                    archived_at=item.archived_at,
                    created_at=item.created_at,
                )
                for item in (media_items or [])
            ],
        )

    def summarize_comment_media(self, photo_count: int, voice_count: int, file_count: int, author_name: str) -> str:
        if photo_count and voice_count and file_count:
            return f"{author_name} добавил фото, голосовое сообщение и файл"
        if photo_count and voice_count:
            return f"{author_name} добавил фото и голосовое сообщение"
        if photo_count and file_count:
            return f"{author_name} добавил фото и файл"
        if voice_count and file_count:
            return f"{author_name} добавил голосовое сообщение и файл"
        if photo_count:
            return f"{author_name} добавил фото"
        if voice_count:
            return f"{author_name} добавил голосовое сообщение"
        if file_count:
            return f"{author_name} добавил файл"
        return f"{author_name} оставил комментарий"

    async def create_comment_with_media_async(
        self,
        *,
        db,
        ticket_id: int,
        author_id: int,
        text: str,
        photos: list[UploadFile] | None = None,
        voice_messages: list[UploadFile] | None = None,
        attachments: list[UploadFile] | None = None,
    ):
        clean_text = (text or "").strip()
        photo_uploads = self.normalize_optional_uploaded_files(photos)
        voice_uploads = self.normalize_optional_uploaded_files(voice_messages)
        attachment_uploads = self.normalize_optional_uploaded_files(attachments)
        if not clean_text and not photo_uploads and not voice_uploads and not attachment_uploads:
            raise self.http_exception_cls(400, "Comment text, photo or voice message is required")

        upload_plan: list[tuple[UploadFile, str, str]] = []
        for upload in photo_uploads:
            if self.detect_comment_media_kind(upload.filename) != "photo":
                raise self.http_exception_cls(400, "Photos field accepts images only")
            upload_plan.append(
                (
                    upload,
                    "photo",
                    self.make_safe_upload_name(
                        upload.filename,
                        ticket_id=ticket_id,
                        allowed_extensions=self.comment_media_extensions,
                    ),
                )
            )
        for upload in voice_uploads:
            if self.detect_comment_media_kind(upload.filename) != "voice":
                raise self.http_exception_cls(400, "Voice messages field accepts audio only")
            upload_plan.append(
                (
                    upload,
                    "voice",
                    self.make_safe_upload_name(
                        upload.filename,
                        ticket_id=ticket_id,
                        allowed_extensions=self.comment_media_extensions,
                    ),
                )
            )
        for upload in attachment_uploads:
            media_kind = self.detect_comment_media_kind(upload.filename)
            upload_plan.append(
                (
                    upload,
                    media_kind,
                    self.make_safe_upload_name(
                        upload.filename,
                        ticket_id=ticket_id,
                        allowed_extensions=self.comment_media_extensions,
                    ),
                )
            )

        comment = self.comment_model(ticket_id=ticket_id, author_id=author_id, text=clean_text)
        db.add(comment)
        db.flush()

        stored_paths: list[str] = []
        media_items: list[object] = []
        try:
            for upload, media_kind, safe_name in upload_plan:
                object_key = self.build_comment_media_object_key(safe_name)
                stored_path, file_hash, file_size = await self.store_upload_file_to_storage_async(upload, object_key)
                stored_paths.append(stored_path)
                media_items.append(
                    self.create_comment_media_record(
                        db=db,
                        comment_id=comment.id,
                        upload=upload,
                        stored_path=stored_path,
                        file_hash=file_hash,
                        file_size=file_size,
                        media_kind=media_kind,
                    )
                )
        except Exception:
            for stored_path in stored_paths:
                self.delete_stored_file(stored_path)
            raise
        return comment, media_items, stored_paths
