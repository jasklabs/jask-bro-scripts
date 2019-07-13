##! An interface for driving the analysis of files, possibly independent of
##! any network protocol over which they're transported.

@load base/bif/file_analysis.bif
@load base/frameworks/analyzer
@load base/frameworks/logging
@load base/utils/site

module Files;

export {

        ## Contains all metadata related to the analysis of a given file.
        ## For the most part, fields here are derived from ones of the same name
        ## in :bro:see:`fa_file`.
        redef record  Info += {
                ## An MD5 digest of the file contents.
                md5: string &log &optional;
                ## A SHA1 digest of the file contents.
                sha1: string &log &optional;
                ## A SHA256 digest of the file contents.
                sha256: string &log &optional;
        };
@load base/frameworks/notice
}

event file_hash(f: fa_file, kind: string, hash: string) &priority=5
        {
        switch ( kind ) {
        case "md5":
                f$info$md5 = hash;
                break;
        case "sha1":
                f$info$sha1 = hash;
                break;
        case "sha256":
                f$info$sha256 = hash;
                break;
        }
        }
