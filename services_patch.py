import os
import re
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def modify_file(file_path):
    logging.info(f"Modifying file: {file_path}")
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    in_method = False
    method_type = None
    method_start_line = ""

    method_patterns = {
        "matchSignatureInSystem": re.compile(r'\.method.*matchSignatureInSystem\(.*\)Z'),
        "matchSignaturesCompat": re.compile(r'\.method.*matchSignaturesCompat\(.*\)Z'),
        "matchSignaturesRecover": re.compile(r'\.method.*matchSignaturesRecover\(.*\)Z'),
        "canSkipForcedPackageVerification": re.compile(r'\.method.*canSkipForcedPackageVerification\(.*\)Z'),
        "checkDowngrade": re.compile(r'\.method public static checkDowngrade\(.*\)Z'),
        "compareSignatures": re.compile(r'\.method public static compareSignatures\(\[Landroid/content/pm/Signature;\[Landroid/content/pm/Signature;\)I'),
        "isApkVerityEnabled": re.compile(r'\.method static isApkVerityEnabled\(\)Z'),
        "isDowngradePermitted": re.compile(r'\.method public static isDowngradePermitted\(IZ\)Z'),
        "verifySignatures": re.compile(r'\.method public static verifySignatures\(Lcom/android/server/pm/PackageSetting;Lcom/android/server/pm/SharedUserSetting;Lcom/android/server/pm/PackageSetting;Landroid/content/pm/SigningDetails;ZZZ\)Z'),
        "isVerificationEnabled": re.compile(r'\.method private isVerificationEnabled\(Landroid/content/pm/PackageInfoLite;I\)Z'),
        "doesSignatureMatchForPermissions": re.compile(r'\.method private doesSignatureMatchForPermissions\(Ljava/lang/String;Lcom/android/server/pm/parsing/pkg/ParsedPackage;I\)Z')
    }

    for line in lines:
        if in_method:
            if line.strip() == '.end method':
                # Add method body based on the identified method type
                modified_lines.append(method_start_line)  # Add the .method line
                if method_type == "matchSignatureInSystem":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 3\n")
                    modified_lines.append("    const/4 p0, 0x0\n")
                    modified_lines.append("    return p0\n")
                elif method_type == "matchSignaturesCompat":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 5\n")
                    modified_lines.append("    const/4 v0, 0x0\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "matchSignaturesRecover":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 5\n")
                    modified_lines.append("    const/4 v0, 0x0\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "canSkipForcedPackageVerification":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 3\n")
                    modified_lines.append("    const/4 v0, 0x1\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "checkDowngrade":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 2\n")
                    modified_lines.append("    .annotation system Ldalvik/annotation/Throws;\n")
                    modified_lines.append("        value = {\n")
                    modified_lines.append("            Lcom/android/server/pm/PackageManagerException;\n")
                    modified_lines.append("        }\n")
                    modified_lines.append("    .end annotation\n")
                    modified_lines.append("    return-void\n")
                elif method_type == "compareSignatures":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 3\n")
                    modified_lines.append("    const/4 v0, 0x0\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "isApkVerityEnabled":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 1\n")
                    modified_lines.append("    const/4 v0, 0x0\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "isDowngradePermitted":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 3\n")
                    modified_lines.append("    const/4 v0, 0x1\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "verifySignatures":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 21\n")
                    modified_lines.append("    .annotation system Ldalvik/annotation/Throws;\n")
                    modified_lines.append("        value = {\n")
                    modified_lines.append("            Lcom/android/server/pm/PackageManagerException;\n")
                    modified_lines.append("        }\n")
                    modified_lines.append("    .end annotation\n")
                    modified_lines.append("    const/4 v1, 0x0\n")
                    modified_lines.append("    return v1\n")
                elif method_type == "isVerificationEnabled":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 4\n")
                    modified_lines.append("    const/4 v0, 0x0\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "doesSignatureMatchForPermissions":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 11\n")
                    modified_lines.append("    const/4 v0, 0x1\n")
                    modified_lines.append("    return v0\n")
                modified_lines.append(line)  # Add the .end method line
                in_method = False
                method_type = None
            else:
                continue

        for key, pattern in method_patterns.items():
            if pattern.search(line):
                in_method = True
                method_type = key
                method_start_line = line  # Save the .method line
                break

        if not in_method:
            modified_lines.append(line)

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for file: {file_path}")


def modify_invoke_interface(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        modified_lines.append(line)
        if 'Lcom/android/server/pm/pkg/AndroidPackage;->isPersistent()Z' in line:
            for j in range(i + 1, min(i + 4, len(lines))):
                if re.match(r'\s*move-result\s+(v\d+)', lines[j]):
                    variable = re.search(r'\s*move-result\s+(v\d+)', lines[j]).group(1)
                    logging.info(f"Replacing line: {lines[j].strip()} with const/4 {variable}, 0x1")
                    modified_lines[-1] = line  # Restore the original line
                    modified_lines.append(f"    const/4 {variable}, 0x0\n")
                    i = j  # Skip the move-result line
                    break
        i += 1

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for file: {file_path}")

def modify_parsing_package_utils(file_path):
    logging.info(f"Modifying ParsingPackageUtils file: {file_path}")
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    for line in lines:
        if "invoke-static {p0, p1, v0}, Landroid/util/apk/ApkSignatureVerifier;->unsafeGetCertsWithoutVerification(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;I)Landroid/content/pm/parsing/result/ParseResult;" in line:
            logging.info("Found target line in ParsingPackageUtils.smali")
            modified_lines.append("    const/4 v0, 0x1\n")
        modified_lines.append(line)

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for ParsingPackageUtils file: {file_path}")


def find_and_modify_smali_files(directory):
    target_files = {
        'PackageManagerServiceUtils.smali': modify_file,
        'InstallPackageHelper.smali': modify_file,
        'VerificationParams.smali': modify_file,
        'ParsingPackageUtils.smali': modify_parsing_package_utils,
    }

    for root, _, files in os.walk(directory):
        for filename in files:
            if filename in target_files:
                file_path = os.path.join(root, filename)
                logging.info(f"Found file: {file_path}")
                target_files[filename](file_path)

                if filename == 'InstallPackageHelper.smali':
                    modify_invoke_interface(file_path)


if __name__ == "__main__":
    directories = ["services_classes", "services_classes2", "services_classes3"]
    for directory in directories:
        if os.path.exists(directory):
            logging.info(f"Processing directory: {directory}")
            find_and_modify_smali_files(directory)
        else:
            logging.warning(f"Directory not found: {directory}")
