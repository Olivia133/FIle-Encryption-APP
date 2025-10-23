/* FileCryptoPro.java
 *
 * Single-file Java Swing application with:
 *  - AES-GCM authenticated encryption (password-derived key via PBKDF2WithHmacSHA256)
 *  - Compress + Encrypt option (ZIP single entry)
 *  - Pastel-themed modern GUI with drag-and-drop, progress bar, status log
 *  - Image visual preview: scrambled preview and restored view after decrypt
 *  - Cross-platform (Windows/macOS/Linux) - Java 11+
 *
 * Usage:
 *   javac FileCryptoPro.java
 *   java FileCryptoPro
 *
 * File format:
 *   MAGIC (7 bytes)            : "OLIPRO1"
 *   FLAGS (1 byte)             : bit0 = compressed (1 = compressed)
 *   SALT (16 bytes)
 *   NONCE (12 bytes)
 *   FILENAME_LEN (2 bytes, big-endian)
 *   FILENAME (UTF-8)
 *   CIPHERTEXT...
 *
 * Author: Assistant (adapted/polished for Olivia's project)
 * Date: 2025-10-09
 */

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.dnd.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/* ----------------- Main class ----------------- */
public class FileCryptoPro extends JFrame {
    private static final byte[] MAGIC = "OLIPRO1".getBytes(StandardCharsets.UTF_8); // 7 bytes
    private static final int SALT_SIZE = 16;
    private static final int NONCE_SIZE = 12; // 96 bits for GCM
    private static final int KEY_BITS = 256;
    private static final int PBKDF2_ITERS = 200_000;
    private static final int GCM_TAG_BITS = 128;

    // flags mask
    private static final byte FLAG_COMPRESSED = 0x01;

    // UI components
    private final JTextField fileField = new JTextField();
    private final JButton browseBtn = new JButton("Browse...");
    private final JRadioButton encryptRadio = new JRadioButton("Encrypt", true);
    private final JRadioButton decryptRadio = new JRadioButton("Decrypt");
    private final JPasswordField passwordField = new JPasswordField();
    private final JCheckBox compressCheck = new JCheckBox("Compress before encrypting");
    private final JTextField outputField = new JTextField();
    private final JButton saveAsBtn = new JButton("Choose Save As...");
    private final JButton processBtn = new JButton("Process");
    private final JProgressBar progressBar = new JProgressBar(0, 100);
    private final JTextArea statusArea = new JTextArea();
    private final JPanel previewPanel = new JPanel(new GridLayout(1,2,8,8));
    private final JLabel originalPreviewLabel = new JLabel("Original (if image)", SwingConstants.CENTER);
    private final JLabel processedPreviewLabel = new JLabel("Preview / Restored", SwingConstants.CENTER);

    private Path selectedFile = null;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                // optional look & feel: system
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {}
            new FileCryptoPro().setVisible(true);
        });
    }

    public FileCryptoPro() {
        super("FileCryptoPro — Olivia");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(940, 700);
        setLocationRelativeTo(null);
        initUI();
    }

    private void initUI() {
        // Pastel theme colors
        Color bg = new Color(245, 246, 250);
        Color panelBg = new Color(250, 245, 250);
        Color accent = new Color(183, 158, 230); // pastel purple
        getContentPane().setBackground(bg);
        setLayout(new BorderLayout(12, 12));

        // Top control panel
        JPanel top = new JPanel();
        top.setBackground(panelBg);
        top.setBorder(new EmptyBorder(12, 12, 12, 12));
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        // File row with drag-drop
        JPanel fileRow = new JPanel(new BorderLayout(8, 8));
        fileRow.setBackground(panelBg);
        JLabel fileLbl = new JLabel("File:");
        fileRow.add(fileLbl, BorderLayout.WEST);
        fileField.setEditable(false);
        fileField.setPreferredSize(new Dimension(400, 28));
        fileRow.add(fileField, BorderLayout.CENTER);
        browseBtn.setBackground(accent);
        browseBtn.setForeground(Color.white);
        fileRow.add(browseBtn, BorderLayout.EAST);
        top.add(fileRow);
        top.add(Box.createVerticalStrut(8));

        // Operation + compress
        JPanel opRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 6));
        opRow.setBackground(panelBg);
        ButtonGroup g = new ButtonGroup();
        g.add(encryptRadio); g.add(decryptRadio);
        opRow.add(new JLabel("Operation:"));
        opRow.add(encryptRadio);
        opRow.add(decryptRadio);
        opRow.add(Box.createHorizontalStrut(20));
        compressCheck.setBackground(panelBg);
        opRow.add(compressCheck);
        top.add(opRow);

        // Password row
        JPanel pwdRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 6));
        pwdRow.setBackground(panelBg);
        pwdRow.add(new JLabel("Secret key / Password:"));
        passwordField.setColumns(28);
        pwdRow.add(passwordField);
        JButton showBtn = new JButton("Show");
        showBtn.addActionListener(e -> {
            if (passwordField.getEchoChar() == (char)0) {
                passwordField.setEchoChar('*');
                showBtn.setText("Show");
            } else {
                passwordField.setEchoChar((char)0);
                showBtn.setText("Hide");
            }
        });
        pwdRow.add(showBtn);
        top.add(pwdRow);

        // Output row
        JPanel outRow = new JPanel(new BorderLayout(8,8));
        outRow.setBackground(panelBg);
        JPanel outLeft = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 6));
        outLeft.setBackground(panelBg);
        outLeft.add(new JLabel("Output (save to):"));
        outputField.setPreferredSize(new Dimension(420,28));
        outLeft.add(outputField);
        outLeft.add(saveAsBtn);
        outRow.add(outLeft, BorderLayout.WEST);
        top.add(outRow);

        // Buttons row
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnRow.setBackground(panelBg);
        processBtn.setBackground(new Color(120, 200, 180)); // pastel green
        btnRow.add(processBtn);
        JButton quitBtn = new JButton("Quit");
        btnRow.add(quitBtn);
        top.add(btnRow);

        // Progress + status
        JPanel progRow = new JPanel(new BorderLayout(8,8));
        progRow.setBackground(panelBg);
        progressBar.setStringPainted(true);
        progRow.add(progressBar, BorderLayout.NORTH);
        statusArea.setEditable(false);
        statusArea.setRows(6);
        JScrollPane statusScroll = new JScrollPane(statusArea);
        progRow.add(statusScroll, BorderLayout.CENTER);
        top.add(Box.createVerticalStrut(6));
        top.add(progRow);

        add(top, BorderLayout.NORTH);

        // Preview panel center (image preview)
        previewPanel.setBackground(bg);
        previewPanel.setBorder(new EmptyBorder(10,12,10,12));
        originalPreviewLabel.setVerticalTextPosition(SwingConstants.BOTTOM);
        originalPreviewLabel.setHorizontalTextPosition(SwingConstants.CENTER);
        processedPreviewLabel.setVerticalTextPosition(SwingConstants.BOTTOM);
        processedPreviewLabel.setHorizontalTextPosition(SwingConstants.CENTER);
        originalPreviewLabel.setBorder(BorderFactory.createLineBorder(new Color(220,220,230)));
        processedPreviewLabel.setBorder(BorderFactory.createLineBorder(new Color(220,220,230)));
        previewPanel.add(originalPreviewLabel);
        previewPanel.add(processedPreviewLabel);
        add(previewPanel, BorderLayout.CENTER);

        // Bottom help area with short instructions
        JTextArea help = new JTextArea(
            "How to use:\n" +
            "1) Drag & drop a file here or use Browse.\n" +
            "2) Choose Encrypt or Decrypt. If Encrypt, you may check 'Compress'.\n" +
            "3) Type your password, choose save location, then Process.\n" +
            "Image preview: if the selected file is an image, the left shows the original and the right shows a scrambled preview (for encryption) or restored image (after decryption).\n"
        );
        help.setEditable(false);
        help.setBackground(bg);
        help.setBorder(new EmptyBorder(8,12,12,12));
        add(help, BorderLayout.SOUTH);

        // Wire events
        browseBtn.addActionListener(e -> onBrowse());
        saveAsBtn.addActionListener(e -> onSaveAs());
        processBtn.addActionListener(e -> onProcess());
        quitBtn.addActionListener(e -> System.exit(0));
        encryptRadio.addActionListener(e -> updateSuggestedOutput());
        decryptRadio.addActionListener(e -> updateSuggestedOutput());

        // Drag-and-drop support for the entire frame
        new DropTarget(this, DnDConstants.ACTION_COPY, new DropTargetAdapter(){
            @Override
            public void drop(DropTargetDropEvent dtde) {
                try {
                    dtde.acceptDrop(DnDConstants.ACTION_COPY);
                    java.util.List<?> dropped = (java.util.List<?>) dtde.getTransferable().getTransferData(java.awt.datatransfer.DataFlavor.javaFileListFlavor);
                    if (!dropped.isEmpty()) {
                        File f = (File) dropped.get(0);
                        setSelectedFile(f.toPath());
                    }
                } catch (Exception ex) {
                    appendStatus("Drop failed: " + ex.getMessage());
                }
            }
        }, true, null);

        // initial state
        updateSuggestedOutput();
    }

    private void onBrowse() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select file to process");
        int res = chooser.showOpenDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            setSelectedFile(chooser.getSelectedFile().toPath());
        }
    }

    private void setSelectedFile(Path p) {
        selectedFile = p;
        fileField.setText(p.toString());
        updateSuggestedOutput();
        appendStatus("Selected: " + p.getFileName());
        // show preview if image
        try {
            if (isImageFile(p)) {
                BufferedImage img = ImageIO.read(p.toFile());
                if (img != null) {
                    showOriginalPreview(img);
                    // compute scrambled preview asynchronously without blocking UI
                    SwingUtilities.invokeLater(() -> {
                        try { BufferedImage scrambled = makeScrambledPreview(img, passwordField.getPassword()); showProcessedPreview(scrambled, "Scrambled Preview"); }
                        catch (Exception ignored) {}
                    });
                } else {
                    showOriginalPreview(null);
                    showProcessedPreview(null, "");
                }
            } else {
                showOriginalPreview(null);
                showProcessedPreview(null, "");
            }
        } catch (IOException ex) {
            appendStatus("Preview load failed: " + ex.getMessage());
        }
    }

    private void onSaveAs() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose save location");
        if (!outputField.getText().isBlank()) chooser.setSelectedFile(new File(outputField.getText()));
        int res = chooser.showSaveDialog(this);
        if (res == JFileChooser.APPROVE_OPTION) {
            outputField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void updateSuggestedOutput() {
        if (selectedFile == null) return;
        String base = selectedFile.toString();
        if (encryptRadio.isSelected()) {
            outputField.setText(base + ".oliproenc");
        } else {
            // if file ends with .oliproenc suggest stripping
            String name = selectedFile.getFileName().toString();
            if (name.endsWith(".oliproenc")) {
                outputField.setText(selectedFile.getParent().resolve(name.substring(0, name.length()-10)).toString());
            } else {
                outputField.setText(base + ".restored");
            }
        }
    }

    private void onProcess() {
        if (selectedFile == null) {
            JOptionPane.showMessageDialog(this, "Please select a file first.", "No file", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String out = outputField.getText().trim();
        if (out.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please choose an output filename.", "No output", JOptionPane.WARNING_MESSAGE);
            return;
        }
        char[] pwd = passwordField.getPassword();
        if (pwd == null || pwd.length == 0) {
            JOptionPane.showMessageDialog(this, "Please enter a password.", "No password", JOptionPane.WARNING_MESSAGE);
            return;
        }
        boolean doEncrypt = encryptRadio.isSelected();
        boolean doCompress = compressCheck.isSelected();

        // Run in background
        processBtn.setEnabled(false);
        SwingWorker<Void, Integer> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    if (doEncrypt) encryptFile(selectedFile, Paths.get(out), pwd, doCompress);
                    else decryptFile(selectedFile, Paths.get(out), pwd);
                } catch (AEADBadTagException ex) {
                    appendStatus("Authentication failed (wrong password or corrupted file).");
                    showError("Authentication failed — wrong password or corrupted file.");
                } catch (IllegalArgumentException ex) {
                    appendStatus("Invalid file format: " + ex.getMessage());
                    showError("Invalid file format: " + ex.getMessage());
                } catch (Exception ex) {
                    appendStatus("Error: " + ex.getMessage());
                    showError("Error: " + ex.getMessage());
                    ex.printStackTrace();
                }
                return null;
            }

            @Override
            protected void done() {
                processBtn.setEnabled(true);
                Arrays.fill(pwd, '\0');
            }
        };

        worker.addPropertyChangeListener(evt -> {
            if ("progress".equals(evt.getPropertyName())) {
                progressBar.setValue((Integer) evt.getNewValue());
            }
        });

        worker.execute();
    }

    /* ----------------- File crypto operations ----------------- */

    private void encryptFile(Path input, Path outPath, char[] password, boolean compress) throws Exception {
        appendStatus("Starting encryption: " + input.getFileName());
        // read file bytes (for demo / project simplicity). For huge files you'd implement streaming.
        byte[] inputBytes = Files.readAllBytes(input);
        int total = inputBytes.length;
        appendStatus("Read " + total + " bytes.");

        // optionally compress
        byte flags = 0;
        byte[] payload;
        if (compress) {
            appendStatus("Compressing before encryption...");
            payload = compressToZipBytes(input.getFileName().toString(), inputBytes);
            flags |= FLAG_COMPRESSED;
            appendStatus("Compressed -> " + payload.length + " bytes.");
        } else {
            payload = inputBytes;
        }

        // derive key & random salt/nonce
        SecureRandom rnd = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        rnd.nextBytes(salt);
        byte[] keyBytes = deriveKey(password, salt);

        // AES-GCM encryption in-memory but update progress by chunks
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        byte[] nonce = new byte[NONCE_SIZE];
        rnd.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcm);

        // process in chunks to give progress updates
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int chunk = 64 * 1024;
        int processed = 0;
        for (int off=0; off<payload.length; off += chunk) {
            int len = Math.min(chunk, payload.length - off);
            byte[] out = cipher.update(payload, off, len);
            if (out != null) bout.write(out);
            processed += len;
            int prog = (int) ( (processed / (double) payload.length) * 85 ); // encryption does 85% of progress
            setProgressSafe(prog);
        }
        // finalize
        byte[] finalBytes = cipher.doFinal();
        if (finalBytes != null && finalBytes.length > 0) bout.write(finalBytes);
        byte[] ciphertext = bout.toByteArray();

        // assemble final file: MAGIC | FLAGS | SALT | NONCE | FILENAME_LEN (2 bytes) | FILENAME bytes | CIPHERTEXT
        byte[] filenameBytes = input.getFileName().toString().getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream fileOut = new ByteArrayOutputStream();
        fileOut.write(MAGIC);
        fileOut.write(flags);
        fileOut.write(salt);
        fileOut.write(nonce);
        fileOut.write(shortToBytes((short)filenameBytes.length));
        fileOut.write(filenameBytes);
        fileOut.write(ciphertext);
        byte[] fullBlob = fileOut.toByteArray();

        // write to disk
        Files.write(outPath, fullBlob, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        setProgressSafe(100);
        appendStatus("Encryption complete. Encrypted file saved to: " + outPath.toString() + " (" + fullBlob.length + " bytes)");
        JOptionPane.showMessageDialog(this, "Encryption successful!\nSaved to:\n" + outPath.toString(), "Success", JOptionPane.INFORMATION_MESSAGE);

        // cleanup key material
        Arrays.fill(keyBytes, (byte)0);
    }

    private void decryptFile(Path input, Path outPath, char[] password) throws Exception {
        appendStatus("Starting decryption: " + input.getFileName());
        byte[] blob = Files.readAllBytes(input);
        int off = 0;
        if (blob.length < MAGIC.length + 1 + SALT_SIZE + NONCE_SIZE + 2) throw new IllegalArgumentException("File too short.");
        // check magic
        for (int i=0;i<MAGIC.length;i++){
            if (blob[i] != MAGIC[i]) throw new IllegalArgumentException("Magic header mismatch.");
        }
        off += MAGIC.length;
        byte flags = blob[off]; off += 1;
        byte[] salt = Arrays.copyOfRange(blob, off, off + SALT_SIZE); off += SALT_SIZE;
        byte[] nonce = Arrays.copyOfRange(blob, off, off + NONCE_SIZE); off += NONCE_SIZE;
        short nameLen = bytesToShort(blob, off); off += 2;
        if (off + nameLen > blob.length) throw new IllegalArgumentException("Invalid filename length.");
        String origName = new String(blob, off, nameLen, StandardCharsets.UTF_8); off += nameLen;
        byte[] ciphertext = Arrays.copyOfRange(blob, off, blob.length);

        // derive key
        byte[] keyBytes = deriveKey(password, salt);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        // decrypt with AES-GCM using chunked updates to provide progress
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_BITS, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcm);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int chunk = 64 * 1024;
        for (int i=0; i<ciphertext.length; i+=chunk) {
            int len = Math.min(chunk, ciphertext.length - i);
            byte[] out = cipher.update(ciphertext, i, len);
            if (out != null) bout.write(out);
            int prog = 10 + (int)( (i / (double)ciphertext.length) * 80 ); // decryption occupies middle of progress
            setProgressSafe(prog);
        }
        byte[] finalBytes = cipher.doFinal(); // AEADBadTagException here on auth failure
        if (finalBytes != null && finalBytes.length > 0) bout.write(finalBytes);
        byte[] payload = bout.toByteArray();

        // if compressed, unzip single entry
        if ((flags & FLAG_COMPRESSED) != 0) {
            appendStatus("Detected compressed payload — decompressing...");
            payload = unzipSingleEntry(payload);
            appendStatus("Decompressed -> " + payload.length + " bytes.");
        }

        // write output to selected path
        Files.write(outPath, payload, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        setProgressSafe(100);
        appendStatus("Decryption complete. Restored file saved to: " + outPath.toString() + " (" + payload.length + " bytes)");
        JOptionPane.showMessageDialog(this, "Decryption successful!\nSaved to:\n" + outPath.toString(), "Success", JOptionPane.INFORMATION_MESSAGE);

        // If restored file is image, show restored preview
        try {
            if (isImageBytes(payload)) {
                ByteArrayInputStream bais = new ByteArrayInputStream(payload);
                BufferedImage restored = ImageIO.read(bais);
                showProcessedPreview(restored, "Restored Image");
            }
        } catch (IOException ignored){}

        Arrays.fill(keyBytes, (byte)0);
    }

    /* ----------------- Utility helpers ----------------- */

    private static byte[] deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERS, KEY_BITS);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return key;
    }

    private static byte[] compressToZipBytes(String entryName, byte[] data) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bout)) {
            ZipEntry e = new ZipEntry(entryName);
            zos.putNextEntry(e);
            zos.write(data);
            zos.closeEntry();
        }
        return bout.toByteArray();
    }

    private static byte[] unzipSingleEntry(byte[] zipBytes) throws IOException {
        try (java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            java.util.zip.ZipEntry e = zis.getNextEntry();
            if (e == null) throw new IOException("ZIP archive contains no entries.");
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int r;
            while ((r = zis.read(buf)) != -1) bout.write(buf, 0, r);
            return bout.toByteArray();
        }
    }

    private static byte[] shortToBytes(short s) {
        return new byte[]{ (byte)((s>>8)&0xff), (byte)(s & 0xff) };
    }

    private static short bytesToShort(byte[] b, int off) {
        return (short)(((b[off]&0xff)<<8) | (b[off+1]&0xff));
    }

    private void setProgressSafe(int v) {
        SwingUtilities.invokeLater(() -> progressBar.setValue(Math.min(100, Math.max(0, v))));
    }

    private void appendStatus(String s) {
        SwingUtilities.invokeLater(() -> {
            statusArea.append(s + "\n");
            statusArea.setCaretPosition(statusArea.getDocument().getLength());
        });
    }

    private void showError(String msg) {
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE));
    }

    /* ----------------- Image preview helpers ----------------- */

    private static boolean isImageFile(Path p) {
        String nm = p.getFileName().toString().toLowerCase();
        return nm.endsWith(".png") || nm.endsWith(".jpg") || nm.endsWith(".jpeg") || nm.endsWith(".bmp") || nm.endsWith(".gif");
    }

    private static boolean isImageBytes(byte[] b) {
        try {
            return ImageIO.read(new ByteArrayInputStream(b)) != null;
        } catch (IOException e) {
            return false;
        }
    }

    private void showOriginalPreview(BufferedImage img) {
        SwingUtilities.invokeLater(() -> {
            if (img == null) {
                originalPreviewLabel.setIcon(null);
                originalPreviewLabel.setText("Original (if image)");
            } else {
                originalPreviewLabel.setText("");
                originalPreviewLabel.setIcon(new ImageIcon(fitImageToLabel(img, originalPreviewLabel.getWidth(), originalPreviewLabel.getHeight())));
            }
        });
    }

    private void showProcessedPreview(BufferedImage img, String caption) {
        SwingUtilities.invokeLater(() -> {
            if (img == null) {
                processedPreviewLabel.setIcon(null);
                processedPreviewLabel.setText(caption.isEmpty() ? "Preview / Restored" : caption);
            } else {
                processedPreviewLabel.setText("");
                processedPreviewLabel.setIcon(new ImageIcon(fitImageToLabel(img, processedPreviewLabel.getWidth(), processedPreviewLabel.getHeight())));
            }
        });
    }

    private static BufferedImage fitImageToLabel(BufferedImage img, int w, int h) {
        if (w <= 0 || h <= 0) { return img; }
        int iw = img.getWidth(), ih = img.getHeight();
        double scale = Math.min(w / (double)iw, h / (double)ih);
        if (scale >= 1.0) return img;
        int nw = (int)(iw * scale), nh = (int)(ih * scale);
        Image scaled = img.getScaledInstance(nw, nh, Image.SCALE_SMOOTH);
        BufferedImage out = new BufferedImage(nw, nh, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = out.createGraphics();
        g2.drawImage(scaled, 0, 0, null);
        g2.dispose();
        return out;
    }

    /**
     * Make a scrambled preview of the image using AES-CTR keystream XOR on pixels.
     * This is only for visualization and uses a derived key from the password and a small nonce.
     */
    private BufferedImage makeScrambledPreview(BufferedImage original, char[] password) {
        try {
            // scale down to at most 300px wide for quick preview
            int maxDim = 300;
            int w = original.getWidth(), h = original.getHeight();
            double scale = Math.min(1.0, maxDim / (double)Math.max(w, h));
            int nw = (int)(w * scale), nh = (int)(h * scale);
            BufferedImage scaled = new BufferedImage(nw, nh, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = scaled.createGraphics();
            g.drawImage(original, 0, 0, nw, nh, null);
            g.dispose();

            // extract ARGB ints
            int[] pixels = scaled.getRGB(0,0,nw,nh,null,0,nw);
            byte[] pixelBytes = intsToBytes(pixels);

            // build small salt & nonce based on image dims (non-secret) + random
            SecureRandom rnd = new SecureRandom();
            byte[] salt = new byte[8]; rnd.nextBytes(salt);
            byte[] nonce = new byte[12]; rnd.nextBytes(nonce);

            // derive key (shorter iterations ok for quick UI)
            byte[] key = deriveKey(password, salt);

            // produce AES-CTR keystream and XOR
            Cipher ctr = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            ctr.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(nonce));
            byte[] keystream = ctr.doFinal(pixelBytes.length <= 0 ? new byte[0] : new byte[pixelBytes.length]); // zeroed bytes encrypted -> keystream
            for (int i=0;i<pixelBytes.length && i<keystream.length;i++) pixelBytes[i] ^= keystream[i];

            // reconstruct ints
            int[] scrambled = bytesToInts(pixelBytes);
            BufferedImage out = new BufferedImage(nw, nh, BufferedImage.TYPE_INT_ARGB);
            out.setRGB(0,0,nw,nh,scrambled,0,nw);

            // zero key material
            Arrays.fill(key, (byte)0);
            return out;
        } catch (Exception ex) {
            return null;
        }
    }

    private static byte[] intsToBytes(int[] arr) {
        byte[] b = new byte[arr.length * 4];
        for (int i=0;i<arr.length;i++){
            int v = arr[i];
            int off = i*4;
            b[off]   = (byte)((v>>24)&0xff);
            b[off+1] = (byte)((v>>16)&0xff);
            b[off+2] = (byte)((v>>8)&0xff);
            b[off+3] = (byte)(v & 0xff);
        }
        return b;
    }
    private static int[] bytesToInts(byte[] b) {
        int n = b.length / 4;
        int[] out = new int[n];
        for (int i=0;i<n;i++){
            int off = i*4;
            int v = ((b[off]&0xff)<<24) | ((b[off+1]&0xff)<<16) | ((b[off+2]&0xff)<<8) | (b[off+3]&0xff);
            out[i] = v;
        }
        return out;
    }

    /* ----------------- End of class ----------------- */
}
