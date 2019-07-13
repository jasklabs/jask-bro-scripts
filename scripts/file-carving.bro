@load base/files/extract

global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["application/x-msdownload"] = "exe", # IE recognizes these as executables
    ["application/x-msdos-program"] = "exe",
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
    ["application/msword"] = "doc",
    ["application/zip"] = "zip",
    ["application/pdf"] = "pdf",
} &default ="";

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( ! meta?$mime_type ) return;
    local ext = "";

    if ( meta?$mime_type )
        ext = ext_map[meta$mime_type];
    if (ext == "") return;

    local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    Files::add_analyzer(f, Files::ANALYZER_MD5, [$extract_filename=fname]);
    Files::add_analyzer(f, Files::ANALYZER_SHA1, [$extract_filename=fname]);
    Files::add_analyzer(f, Files::ANALYZER_SHA256, [$extract_filename=fname]);
    }
