/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2007 Kenny Root, Jeffrey Sharkey
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connectbot;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EventListener;
import java.util.List;

import org.connectbot.bean.PubkeyBean;
import org.connectbot.service.TerminalManager;
import org.connectbot.util.PubkeyDatabase;
import org.connectbot.util.PubkeyUtils;
import org.openintents.intents.FileManagerIntents;

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.crypto.PEMDecoder;
import com.trilead.ssh2.crypto.PEMStructure;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.IBinder;
import android.view.KeyEvent;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ImageButton;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import androidx.appcompat.widget.PopupMenu;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import android.text.ClipboardManager;
import android.util.Log;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.piv.PivKeyReference;
import de.cotech.hw.piv.PivSecurityKey;
import de.cotech.hw.piv.PivSecurityKeyDialogFragment;
import de.cotech.hw.openpgp.OpenPgpSecurityKey;
import de.cotech.hw.openpgp.pairedkey.PairedSecurityKey;
import de.cotech.hw.ui.SecurityKeyDialogInterface;
import de.cotech.hw.ui.SecurityKeyDialogOptions;
import de.cotech.hw.openpgp.OpenPgpSecurityKeyDialogFragment;
import de.cotech.hw.ui.SecurityKeyDialogFragment;

/**
 * List public keys in database by nickname and describe their properties. Allow users to import,
 * generate, rename, and delete key pairs.
 *
 * @author Kenny Root
 */
public class PubkeyListActivity extends AppCompatListActivity implements EventListener, PubkeyAddBottomSheetDialog.PubkeyAddBottomSheetListener {
	public final static String TAG = "CB.PubkeyListActivity";

	private static final int MAX_KEYFILE_SIZE = 32768;
	private static final int REQUEST_CODE_PICK_FILE = 1;

	// Constants for AndExplorer's file picking intent
	private static final String ANDEXPLORER_TITLE = "explorer_title";
	private static final String MIME_TYPE_ANDEXPLORER_FILE = "vnd.android.cursor.dir/lysesoft.andexplorer.file";

	protected ClipboardManager clipboard;

	private TerminalManager bound = null;

	private WebView webView;
	private BottomSheetBehavior bottomSheetBehavior;


	private ServiceConnection connection = new ServiceConnection() {
		@Override
		public void onServiceConnected(ComponentName className, IBinder service) {
			bound = ((TerminalManager.TerminalBinder) service).getService();

			// update our listview binder to find the service
			updateList();
		}

		@Override
		public void onServiceDisconnected(ComponentName className) {
			bound = null;
			updateList();
		}
	};

	@Override
	public void onStart() {
		super.onStart();

		bindService(new Intent(this, TerminalManager.class), connection, Context.BIND_AUTO_CREATE);

		updateList();
	}

	@Override
	public void onStop() {
		super.onStop();

		unbindService(connection);
	}

	@Override
	public void onCreate(Bundle icicle) {
		super.onCreate(icicle);
		setContentView(R.layout.act_pubkeylist_shop);

		mListView = findViewById(R.id.list);
		mListView.setHasFixedSize(true);
		mListView.setLayoutManager(new LinearLayoutManager(this));
		mListView.addItemDecoration(new ListItemDecoration(this));

		mEmptyView = findViewById(R.id.empty);

		registerForContextMenu(mListView);

		clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);

		setupShop();
	}

	@SuppressLint("SetJavaScriptEnabled")
	private void setupShop() {
		ConstraintLayout bottomSheet = findViewById(R.id.shopBottomSheet);
		bottomSheetBehavior = BottomSheetBehavior.from(bottomSheet);

		boolean showShop = getSharedPreferences("termbot_preference", MODE_PRIVATE).getBoolean("termbot_showshop", true);
		if (!showShop) {
			bottomSheetBehavior.setState(BottomSheetBehavior.STATE_HIDDEN);
			return;
		}

		webView = findViewById(R.id.webView);
		webView.setWebViewClient(new WebViewClient());
		webView.getSettings().setJavaScriptEnabled(true);
		String packageName = getPackageName();
		String url = "https://hwsecurity.dev/?pk_campaign=sdk&pk_source=" + packageName;
		webView.loadUrl(url);

		ImageView shopImageCard = findViewById(R.id.webImageCard);

		ImageButton shopMenuButton = findViewById(R.id.webMenuButton);
		shopMenuButton.setOnClickListener(this::showShopMenu);

		bottomSheetBehavior.setBottomSheetCallback(new BottomSheetBehavior.BottomSheetCallback() {
			@Override
			public void onStateChanged(@NonNull View view, int state) {
			}

			@Override
			public void onSlide(@NonNull View view, float slideOffset) {
				shopImageCard.setAlpha(1 - slideOffset);
			}
		});

		View shopViewClick = findViewById(R.id.webViewClick);
		shopViewClick.setOnClickListener(v -> {
			if (bottomSheetBehavior.getState() == BottomSheetBehavior.STATE_EXPANDED) {
				bottomSheetBehavior.setState(BottomSheetBehavior.STATE_COLLAPSED);
			} else {
				bottomSheetBehavior.setState(BottomSheetBehavior.STATE_EXPANDED);
			}
		});
	}

	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		if (event.getAction() == KeyEvent.ACTION_DOWN) {
			if (keyCode == KeyEvent.KEYCODE_BACK) {
				if (webView.canGoBack()) {
					webView.goBack();
				} else {
					finish();
				}
				return true;
			}

		}
		return super.onKeyDown(keyCode, event);
	}

	public void showShopMenu(View v) {
		PopupMenu popup = new PopupMenu(this, v);
		popup.setOnMenuItemClickListener(item -> {
			switch (item.getItemId()) {
			case R.id.webOpenInBrowser:
				String packageName = getPackageName();
				String url = "https://hwsecurity.dev/?pk_campaign=sdk&pk_source=" + packageName;
				Intent i = new Intent(Intent.ACTION_VIEW);
				i.setData(Uri.parse(url));
				startActivity(i);
				return true;
			case R.id.webShare:
				Intent sendIntent = new Intent();
				sendIntent.setAction(Intent.ACTION_SEND);
				sendIntent.putExtra(Intent.EXTRA_TEXT, "Get the Hardware Security SDK at https://hwsecurity.dev");
				sendIntent.setType("text/plain");
				startActivity(sendIntent);
				return true;
			case R.id.webHide:
				bottomSheetBehavior.setState(BottomSheetBehavior.STATE_HIDDEN);
				getSharedPreferences("termbot_preference", MODE_PRIVATE)
						.edit()
						.putBoolean("termbot_showshop", false)
						.apply();
				return true;
			default:
				return false;
			}
		});
		MenuInflater inflater = popup.getMenuInflater();
		inflater.inflate(R.menu.web_menu, popup.getMenu());
		popup.show();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		MenuInflater inflater = getMenuInflater();
		inflater.inflate(R.menu.pubkey_list_activity_menu, menu);
		return super.onCreateOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case R.id.add_new_key_icon:
			PubkeyAddBottomSheetDialog addDialog = PubkeyAddBottomSheetDialog.newInstance();
			addDialog.show(getSupportFragmentManager(), PubkeyAddBottomSheetDialog.TAG);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	@Override
	public void onBottomSheetAddKey() {
		startActivity(new Intent(this, GeneratePubkeyActivity.class));
	}

	@Override
	public void onBottomSheetImportKey() {
		importExistingKey();
	}

	@Override
	public void onBottomSheetAddSecurityKey() {
		addSecurityKey();
	}

	@Override
	public void onBottomSheetAddPIVSecurityKey() {
		addPIVSecurityKey();
	}

	@Override
	public void onBottomSheetSetupSecurityKey(OpenPgpSecurityKey.AlgorithmConfig algorithmConfig) {
		setupSecurityKey(algorithmConfig);
	}

	private boolean importExistingKey() {
		Uri sdcard = Uri.fromFile(Environment.getExternalStorageDirectory());
		String pickerTitle = getString(R.string.pubkey_list_pick);

		if (Build.VERSION.SDK_INT >= 19 && importExistingKeyKitKat()) {
			return true;
		} else {
			return importExistingKeyOpenIntents(sdcard, pickerTitle)
					|| importExistingKeyAndExplorer(sdcard, pickerTitle) || pickFileSimple();
		}
	}

	private void addSecurityKey() {
		SecurityKeyDialogOptions options = SecurityKeyDialogOptions.builder()
				.setPinMode(SecurityKeyDialogOptions.PinMode.NO_PIN_INPUT)
				.setShowReset(true)
				.setShowSdkLogo(true)
				.setPreventScreenshots(!BuildConfig.DEBUG)
				.setTitle(getString(R.string.pubkey_add_security_key))
				.setTheme(R.style.SecurityKeyDialog)
				.build();

		SecurityKeyDialogFragment<OpenPgpSecurityKey> securityKeyDialogFragment = OpenPgpSecurityKeyDialogFragment.newInstance(options);
		securityKeyDialogFragment.setSecurityKeyDialogCallback((SecurityKeyDialogInterface.SecurityKeyDialogCallback<OpenPgpSecurityKey>) (securityKeyDialogInterface, openPgpSecurityKey, pinProvider) -> {
			new Thread(() -> {
				try {
					PublicKey publicKey = SecurityKey25519Converter.hwsecurityToConnectbot(openPgpSecurityKey.retrieveAuthenticationPublicKey());
					String nickname = openPgpSecurityKey.getSecurityKeyName() + " (" + openPgpSecurityKey.getSerialNumber() + ")";

					securityKeyDialogFragment.postRunnable(() -> {
						securityKeyDialogInterface.successAndDismiss();
						addSecurityKey(publicKey, nickname, "openpgp");
					});
				} catch (IOException e) {
					securityKeyDialogFragment.postError(e);
				}
			}).start();
		});
		securityKeyDialogFragment.show(getSupportFragmentManager());
	}

	private void addPIVSecurityKey() {
		SecurityKeyDialogOptions options = SecurityKeyDialogOptions.builder()
				.setPinMode(SecurityKeyDialogOptions.PinMode.NO_PIN_INPUT)
				.setShowReset(true)
				.setShowSdkLogo(true)
				.setPreventScreenshots(!BuildConfig.DEBUG)
				.setTitle(getString(R.string.pubkey_add_piv_security_key))
				.setTheme(R.style.SecurityKeyDialog)
				.build();

		SecurityKeyDialogFragment<PivSecurityKey> securityKeyDialogFragment = PivSecurityKeyDialogFragment.newInstance(options);
		securityKeyDialogFragment.setSecurityKeyDialogCallback((SecurityKeyDialogInterface.SecurityKeyDialogCallback<PivSecurityKey>) (securityKeyDialogInterface, pivSecurityKey, pinProvider) -> {
			new Thread(() -> {
				try { 

					SecurityKeyAuthenticator authenticator = pivSecurityKey.createSecurityKeyAuthenticator(pinProvider, PivKeyReference.AUTHENTICATION);
					String subject = "";

					try {
						byte[] certBytes = authenticator.retrieveCertificateData();
						CertificateFactory fact = CertificateFactory.getInstance("X.509");
						X509Certificate certificate = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(certBytes));
						subject = certificate.getSubjectX500Principal().getName();
					}
					catch (CertificateException ce) {
						Log.e(TAG, "Couldn't retrieve certificate", ce);
					}

					String nickname = subject.equals("") ? "PIV key" : subject;

					PublicKey publicKey = authenticator.retrievePublicKey();

					securityKeyDialogFragment.postRunnable(() -> {
						securityKeyDialogInterface.successAndDismiss();
						addSecurityKey(publicKey, nickname, "piv");
					});
				} catch (IOException e) {
					securityKeyDialogFragment.postError(e);
				}
			}).start();
		});
		securityKeyDialogFragment.show(getSupportFragmentManager());
	}


	private void setupSecurityKey(OpenPgpSecurityKey.AlgorithmConfig algorithmConfig) {
		SecurityKeyDialogOptions options = SecurityKeyDialogOptions.builder()
				.setPinMode(SecurityKeyDialogOptions.PinMode.SETUP)
				.setShowSdkLogo(true)
				.setPreventScreenshots(!BuildConfig.DEBUG)
				.setTitle(getString(R.string.pubkey_setup_security_key))
				.setTheme(R.style.SecurityKeyDialog)
				.build();

		SecurityKeyDialogFragment<OpenPgpSecurityKey> securityKeyDialogFragment = OpenPgpSecurityKeyDialogFragment.newInstance(options);
		securityKeyDialogFragment.setSecurityKeyDialogCallback((SecurityKeyDialogInterface.SecurityKeyDialogCallback<OpenPgpSecurityKey>) (securityKeyDialogInterface, openPgpSecurityKey, pinProvider) -> {
			new Thread(() -> {
				try {
					PairedSecurityKey pairedSecurityKey = openPgpSecurityKey.setupPairedKey(pinProvider, algorithmConfig);
					PublicKey publicKey = SecurityKey25519Converter.hwsecurityToConnectbot(pairedSecurityKey.getAuthPublicKey());
					String nickname = openPgpSecurityKey.getSecurityKeyName() + " (" + openPgpSecurityKey.getSerialNumber() + ")";

					securityKeyDialogFragment.postRunnable(() -> {
						securityKeyDialogInterface.successAndDismiss();
						addSecurityKey(publicKey, nickname, "openpgp");
					});
				} catch (IOException e) {
					securityKeyDialogFragment.postError(e);
				}
			}).start();
		});
		securityKeyDialogFragment.show(getSupportFragmentManager());
	}

	private void addSecurityKey(PublicKey publicKey, String nickname, String securityKeyType) {
		PubkeyBean pubkey = new PubkeyBean();
		pubkey.setSecurityKey(true);
		pubkey.setSecurityKeyType(securityKeyType);
		pubkey.setPublicKey(publicKey.getEncoded());
		pubkey.setNickname(nickname);
		String algorithm = convertAlgorithmName(publicKey.getAlgorithm());
		pubkey.setType(algorithm);

		PubkeyDatabase pubkeyDb = PubkeyDatabase.get(this);
		pubkeyDb.savePubkey(pubkey);

		updateList();
	}

	/**
	 * Fires an intent to spin up the "file chooser" UI and select a private key.
	 */
	@TargetApi(19)
	public boolean importExistingKeyKitKat() {
		// ACTION_OPEN_DOCUMENT is the intent to choose a file via the system's file
		// browser.
		Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);

		// Filter to only show results that can be "opened", such as a
		// file (as opposed to a list of contacts or timezones)
		intent.addCategory(Intent.CATEGORY_OPENABLE);

		// PKCS#8 MIME types aren't widely supported, so we'll try */* fro now.
		intent.setType("*/*");

		try {
			startActivityForResult(intent, REQUEST_CODE_PICK_FILE);
			return true;
		} catch (ActivityNotFoundException e) {
			return false;
		}
	}

	/**
	 * Imports an existing key using the OpenIntents-style request.
	 */
	private boolean importExistingKeyOpenIntents(Uri sdcard, String pickerTitle) {
		// Try to use OpenIntent's file browser to pick a file
		Intent intent = new Intent(FileManagerIntents.ACTION_PICK_FILE);
		intent.setData(sdcard);
		intent.putExtra(FileManagerIntents.EXTRA_TITLE, pickerTitle);
		intent.putExtra(FileManagerIntents.EXTRA_BUTTON_TEXT, getString(android.R.string.ok));

		try {
			startActivityForResult(intent, REQUEST_CODE_PICK_FILE);
			return true;
		} catch (ActivityNotFoundException e) {
			return false;
		}
	}

	private boolean importExistingKeyAndExplorer(Uri sdcard, String pickerTitle) {
		Intent intent;
		intent = new Intent(Intent.ACTION_PICK);
		intent.setDataAndType(sdcard, MIME_TYPE_ANDEXPLORER_FILE);
		intent.putExtra(ANDEXPLORER_TITLE, pickerTitle);

		try {
			startActivityForResult(intent, REQUEST_CODE_PICK_FILE);
			return true;
		} catch (ActivityNotFoundException e) {
			return false;
		}
	}

	/**
	 * Builds a simple list of files to pick from.
	 */
	private boolean pickFileSimple() {
		// build list of all files in sdcard root
		final File sdcard = Environment.getExternalStorageDirectory();
		Log.d(TAG, sdcard.toString());

		// Don't show a dialog if the SD card is completely absent.
		final String state = Environment.getExternalStorageState();
		if (!Environment.MEDIA_MOUNTED_READ_ONLY.equals(state)
				&& !Environment.MEDIA_MOUNTED.equals(state)) {
			new androidx.appcompat.app.AlertDialog.Builder(
					PubkeyListActivity.this, R.style.AlertDialogTheme)
					.setMessage(R.string.alert_sdcard_absent)
					.setNegativeButton(android.R.string.cancel, null).create().show();
			return true;
		}

		List<String> names = new ArrayList<>();
		{
			File[] files = sdcard.listFiles();
			if (files != null) {
				for (File file : sdcard.listFiles()) {
					if (file.isDirectory()) continue;
					names.add(file.getName());
				}
			}
		}
		Collections.sort(names);

		final String[] namesList = names.toArray(new String[] {});
		Log.d(TAG, names.toString());

		// prompt user to select any file from the sdcard root
		new androidx.appcompat.app.AlertDialog.Builder(
				PubkeyListActivity.this, R.style.AlertDialogTheme)
				.setTitle(R.string.pubkey_list_pick)
				.setItems(namesList, new OnClickListener() {
					@Override
					public void onClick(DialogInterface arg0, int arg1) {
						String name = namesList[arg1];

						readKeyFromFile(Uri.fromFile(new File(sdcard, name)));
					}
				})
				.setNegativeButton(android.R.string.cancel, null).create().show();

		return true;
	}

	protected void handleAddKey(final PubkeyBean pubkey) {
		if (pubkey.isEncrypted()) {
			final View view = View.inflate(this, R.layout.dia_password, null);
			final EditText passwordField = view.findViewById(android.R.id.text1);

			new androidx.appcompat.app.AlertDialog.Builder(
					PubkeyListActivity.this, R.style.AlertDialogTheme)
					.setView(view)
					.setPositiveButton(R.string.pubkey_unlock, new DialogInterface.OnClickListener() {
						@Override
						public void onClick(DialogInterface dialog, int which) {
							handleAddKey(pubkey, passwordField.getText().toString());
						}
					})
					.setNegativeButton(android.R.string.cancel, null).create().show();
		} else {
			handleAddKey(pubkey, null);
		}
	}

	protected void handleAddKey(PubkeyBean keybean, String password) {
		KeyPair pair = null;
		try {
			pair = PubkeyUtils.convertToKeyPair(keybean, password);
		} catch (PubkeyUtils.BadPasswordException e) {
			String message = getResources().getString(R.string.pubkey_failed_add, keybean.getNickname());
			Toast.makeText(PubkeyListActivity.this, message, Toast.LENGTH_LONG).show();
		}

		if (pair == null) {
			return;
		}

		Log.d(TAG, String.format("Unlocked key '%s'", keybean.getNickname()));

		// save this key in memory
		bound.addKey(keybean, pair, true);

		updateList();
	}

	protected void updateList() {
		PubkeyDatabase pubkeyDb = PubkeyDatabase.get(PubkeyListActivity.this);

		mAdapter = new PubkeyAdapter(this, pubkeyDb.allPubkeys());
		mListView.setAdapter(mAdapter);
		adjustViewVisibility();
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent resultData) {
		super.onActivityResult(requestCode, resultCode, resultData);

		switch (requestCode) {
		case REQUEST_CODE_PICK_FILE:
			if (resultCode == RESULT_OK && resultData != null) {
				Uri uri = resultData.getData();
				try {
					if (uri != null) {
						readKeyFromFile(uri);
					} else {
						String filename = resultData.getDataString();
						if (filename != null) {
							readKeyFromFile(Uri.parse(filename));
						}
					}
				} catch (IllegalArgumentException e) {
					Log.e(TAG, "Couldn't read from picked file", e);
				}
			}
			break;
		}
	}

	public static byte[] getBytesFromInputStream(InputStream is, int maxSize) throws IOException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		byte[] buffer = new byte[0xFFFF];

		for (int len; (len = is.read(buffer)) != -1 && os.size() < maxSize; ) {
			os.write(buffer, 0, len);
		}

		if (os.size() >= maxSize) {
			throw new IOException("File was too big");
		}

		os.flush();
		return os.toByteArray();
	}

	private KeyPair readPKCS8Key(byte[] keyData) {
		BufferedReader reader = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(keyData)));

		// parse the actual key once to check if its encrypted
		// then save original file contents into our database
		try {
			ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();

			String line;
			boolean inKey = false;
			while ((line = reader.readLine()) != null) {
				if (line.equals(PubkeyUtils.PKCS8_START)) {
					inKey = true;
				} else if (line.equals(PubkeyUtils.PKCS8_END)) {
					break;
				} else if (inKey) {
					keyBytes.write(line.getBytes("US-ASCII"));
				}
			}

			if (keyBytes.size() > 0) {
				byte[] decoded = Base64.decode(keyBytes.toString().toCharArray());

				return PubkeyUtils.recoverKeyPair(decoded);
			}
		} catch (Exception e) {
			return null;
		}
		return null;
	}

	/**
	 * @param uri URI to private key to read.
	 */
	private void readKeyFromFile(Uri uri) {
		PubkeyBean pubkey = new PubkeyBean();

		// find the exact file selected
		pubkey.setNickname(uri.getLastPathSegment());

		byte[] keyData;
		try {
			ContentResolver resolver = getContentResolver();
			keyData = getBytesFromInputStream(resolver.openInputStream(uri), MAX_KEYFILE_SIZE);
		} catch (IOException e) {
			Toast.makeText(PubkeyListActivity.this,
					R.string.pubkey_import_parse_problem,
					Toast.LENGTH_LONG).show();
			return;
		}

		KeyPair kp;
		if ((kp = readPKCS8Key(keyData)) != null) {
			String algorithm = convertAlgorithmName(kp.getPrivate().getAlgorithm());
			pubkey.setType(algorithm);
			pubkey.setPrivateKey(kp.getPrivate().getEncoded());
			pubkey.setPublicKey(kp.getPublic().getEncoded());
		} else {
			try {
				PEMStructure struct = PEMDecoder.parsePEM(new String(keyData).toCharArray());
				boolean encrypted = PEMDecoder.isPEMEncrypted(struct);
				pubkey.setEncrypted(encrypted);
				if (!encrypted) {
					kp = PEMDecoder.decode(struct, null);
					String algorithm = convertAlgorithmName(kp.getPrivate().getAlgorithm());
					pubkey.setType(algorithm);
					pubkey.setPrivateKey(kp.getPrivate().getEncoded());
					pubkey.setPublicKey(kp.getPublic().getEncoded());
				} else {
					pubkey.setType(PubkeyDatabase.KEY_TYPE_IMPORTED);
					pubkey.setPrivateKey(keyData);
				}
			} catch (IOException e) {
				Log.e(TAG, "Problem parsing imported private key", e);
				Toast.makeText(PubkeyListActivity.this, R.string.pubkey_import_parse_problem, Toast.LENGTH_LONG).show();
			}
		}

		// write new value into database
		PubkeyDatabase pubkeyDb = PubkeyDatabase.get(this);
		pubkeyDb.savePubkey(pubkey);

		updateList();
	}

	private String convertAlgorithmName(String algorithm) {
		if ("EdDSA".equals(algorithm)) {
			return PubkeyDatabase.KEY_TYPE_ED25519;
		} else {
			return algorithm;
		}
	}

	public class PubkeyViewHolder extends ItemViewHolder {
		public final ImageView icon;
		public final TextView nickname;
		public final TextView caption;

		public PubkeyBean pubkey;

		public PubkeyViewHolder(View v) {
			super(v);

			icon = v.findViewById(android.R.id.icon);
			nickname = v.findViewById(android.R.id.text1);
			caption = v.findViewById(android.R.id.text2);
		}

		@Override
		public void onClick(View v) {
			if (pubkey.isSecurityKey()) {
				return;
			}

			boolean loaded = bound != null && bound.isKeyLoaded(pubkey.getNickname());

			// handle toggling key in-memory on/off
			if (loaded) {
				bound.removeKey(pubkey.getNickname());
				updateList();
			} else {
				handleAddKey(pubkey);
			}
		}

		@Override
		public void onCreateContextMenu(ContextMenu menu, View v, ContextMenu.ContextMenuInfo menuInfo) {
			// Create menu to handle deleting and editing pubkey
			menu.setHeaderTitle(pubkey.getNickname());

			// TODO: option load/unload key from in-memory list
			// prompt for password as needed for passworded keys

			// cant change password or clipboard imported keys
			final boolean imported = PubkeyDatabase.KEY_TYPE_IMPORTED.equals(pubkey.getType());
			final boolean loaded = bound != null && bound.isKeyLoaded(pubkey.getNickname());

			MenuItem load = menu.add(loaded ? R.string.pubkey_memory_unload : R.string.pubkey_memory_load);
			load.setEnabled(!pubkey.isSecurityKey());
			load.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					if (loaded) {
						bound.removeKey(pubkey.getNickname());
						updateList();
					} else {
						handleAddKey(pubkey);
						//bound.addKey(nickname, trileadKey);
					}
					return true;
				}
			});

			MenuItem onstartToggle = menu.add(R.string.pubkey_load_on_start);
			onstartToggle.setEnabled(!pubkey.isEncrypted() && !pubkey.isSecurityKey());
			onstartToggle.setCheckable(true);
			onstartToggle.setChecked(pubkey.isStartup());
			onstartToggle.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					// toggle onstart status
					pubkey.setStartup(!pubkey.isStartup());
					PubkeyDatabase pubkeyDb = PubkeyDatabase.get(PubkeyListActivity.this);
					pubkeyDb.savePubkey(pubkey);
					updateList();
					return true;
				}
			});

			MenuItem copyPublicToClipboard = menu.add(R.string.pubkey_copy_public);
			copyPublicToClipboard.setEnabled(!imported);
			copyPublicToClipboard.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					try {
						PublicKey pk = PubkeyUtils.decodePublic(pubkey.getPublicKey(), pubkey.getType());
						String openSSHPubkey = PubkeyUtils.convertToOpenSSHFormat(pk, pubkey.getNickname());

						clipboard.setText(openSSHPubkey);
					} catch (Exception e) {
						Log.d(TAG, "Error converting to OpenSSH format", e);
					}
					return true;
				}
			});

			MenuItem copyPrivateToClipboard = menu.add(R.string.pubkey_copy_private);
			copyPrivateToClipboard.setEnabled((!pubkey.isEncrypted() || imported) && !pubkey.isSecurityKey());
			copyPrivateToClipboard.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					try {
						String data = null;

						if (imported)
							data = new String(pubkey.getPrivateKey());
						else {
							PrivateKey pk = PubkeyUtils.decodePrivate(pubkey.getPrivateKey(), pubkey.getType());
							data = PubkeyUtils.exportPEM(pk, null);
						}

						clipboard.setText(data);
					} catch (Exception e) {
						Log.d(TAG, "Error copying private key", e);
					}
					return true;
				}
			});

			MenuItem changePassword = menu.add(R.string.pubkey_change_password);
			changePassword.setEnabled(!imported && !pubkey.isSecurityKey());
			changePassword.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					final View changePasswordView =
							View.inflate(PubkeyListActivity.this, R.layout.dia_changepassword, null);
					changePasswordView.findViewById(R.id.old_password_prompt)
							.setVisibility(pubkey.isEncrypted() ? View.VISIBLE : View.GONE);
					new androidx.appcompat.app.AlertDialog.Builder(
							PubkeyListActivity.this, R.style.AlertDialogTheme)
							.setView(changePasswordView)
							.setPositiveButton(R.string.button_change, new DialogInterface.OnClickListener() {
								@Override
								public void onClick(DialogInterface dialog, int which) {
									String oldPassword = ((EditText) changePasswordView.findViewById(R.id.old_password)).getText().toString();
									String password1 = ((EditText) changePasswordView.findViewById(R.id.password1)).getText().toString();
									String password2 = ((EditText) changePasswordView.findViewById(R.id.password2)).getText().toString();

									if (!password1.equals(password2)) {
										new androidx.appcompat.app.AlertDialog.Builder(
												PubkeyListActivity.this,
												R.style.AlertDialogTheme)
												.setMessage(R.string.alert_passwords_do_not_match_msg)
												.setPositiveButton(android.R.string.ok, null)
												.create().show();
										return;
									}

									try {
										if (!pubkey.changePassword(oldPassword, password1))
											new androidx.appcompat.app.AlertDialog.Builder(
													PubkeyListActivity.this,
													R.style.AlertDialogTheme)
													.setMessage(R.string.alert_wrong_password_msg)
													.setPositiveButton(android.R.string.ok, null)
													.create().show();
										else {
											PubkeyDatabase pubkeyDb = PubkeyDatabase.get(PubkeyListActivity.this);
											pubkeyDb.savePubkey(pubkey);
											updateList();
										}
									} catch (Exception e) {
										Log.e(TAG, "Could not change private key password", e);
										new androidx.appcompat.app.AlertDialog.Builder(
												PubkeyListActivity.this,
												R.style.AlertDialogTheme)
												.setMessage(R.string.alert_key_corrupted_msg)
												.setPositiveButton(android.R.string.ok, null)
												.create().show();
									}
								}
							})
							.setNegativeButton(android.R.string.cancel, null).create().show();

					return true;
				}
			});

			MenuItem confirmUse = menu.add(R.string.pubkey_confirm_use);
			confirmUse.setCheckable(true);
			confirmUse.setChecked(pubkey.isConfirmUse());
			confirmUse.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					// toggle confirm use
					pubkey.setConfirmUse(!pubkey.isConfirmUse());
					PubkeyDatabase pubkeyDb = PubkeyDatabase.get(PubkeyListActivity.this);
					pubkeyDb.savePubkey(pubkey);
					updateList();
					return true;
				}
			});

			MenuItem rename = menu.add(R.string.pubkey_rename);
			rename.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					final EditText edittext = new EditText(PubkeyListActivity.this);
					edittext.setText(pubkey.getNickname());
					// prompt user to make sure they really want this
					new androidx.appcompat.app.AlertDialog.Builder(
							PubkeyListActivity.this, R.style.AlertDialogTheme)
							.setView(edittext)
							.setMessage(getString(R.string.rename_message, pubkey.getNickname()))
							.setPositiveButton(R.string.rename_pos, new DialogInterface.OnClickListener() {
								@Override
								public void onClick(DialogInterface dialog, int which) {

									// dont forget to remove from in-memory
									if (loaded) {
										bound.removeKey(pubkey.getNickname());
									}

									// rename in database and update gui
									PubkeyDatabase pubkeyDb = PubkeyDatabase.get(PubkeyListActivity.this);
									pubkeyDb.renamePubkey(pubkey, edittext.getText().toString());
									updateList();
								}
							})
							.setNegativeButton(R.string.rename_neg, null).create().show();

					return true;
				}
			});

			MenuItem delete = menu.add(R.string.pubkey_delete);
			delete.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					// prompt user to make sure they really want this
					new androidx.appcompat.app.AlertDialog.Builder(
							PubkeyListActivity.this, R.style.AlertDialogTheme)
							.setMessage(getString(R.string.delete_message, pubkey.getNickname()))
							.setPositiveButton(R.string.delete_pos, new DialogInterface.OnClickListener() {
								@Override
								public void onClick(DialogInterface dialog, int which) {

									// dont forget to remove from in-memory
									if (loaded) {
										bound.removeKey(pubkey.getNickname());
									}

									// delete from backend database and update gui
									PubkeyDatabase pubkeyDb = PubkeyDatabase.get(PubkeyListActivity.this);
									pubkeyDb.deletePubkey(pubkey);
									updateList();
								}
							})
							.setNegativeButton(R.string.delete_neg, null).create().show();

					return true;
				}
			});
		}
	}

	@VisibleForTesting
	private class PubkeyAdapter extends ItemAdapter {
		private final List<PubkeyBean> pubkeys;

		public PubkeyAdapter(Context context, List<PubkeyBean> pubkeys) {
			super(context);
			this.pubkeys = pubkeys;
		}

		@Override
		public PubkeyViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
			View v = LayoutInflater.from(parent.getContext())
					.inflate(R.layout.item_pubkey, parent, false);
			return new PubkeyViewHolder(v);
		}

		@Override
		public void onBindViewHolder(ItemViewHolder holder, int position) {
			PubkeyViewHolder pubkeyHolder = (PubkeyViewHolder) holder;

			PubkeyBean pubkey = pubkeys.get(position);
			pubkeyHolder.pubkey = pubkey;
			if (pubkey == null) {
				// Well, something bad happened. We can't continue.
				Log.e("PubkeyAdapter", "Pubkey bean is null!");

				pubkeyHolder.nickname.setText("Error during lookup");
			} else {
				pubkeyHolder.nickname.setText(pubkey.getNickname());
			}

			boolean imported = PubkeyDatabase.KEY_TYPE_IMPORTED.equals(pubkey.getType());

			if (imported) {
				try {
					PEMStructure struct = PEMDecoder.parsePEM(new String(pubkey.getPrivateKey()).toCharArray());
					String type;
					if (struct.pemType == PEMDecoder.PEM_RSA_PRIVATE_KEY) {
						type = "RSA";
					} else if (struct.pemType == PEMDecoder.PEM_DSA_PRIVATE_KEY) {
						type = "DSA";
					} else if (struct.pemType == PEMDecoder.PEM_EC_PRIVATE_KEY) {
						type = "EC";
					} else if (struct.pemType == PEMDecoder.PEM_OPENSSH_PRIVATE_KEY) {
						type = "OpenSSH";
					} else {
						throw new RuntimeException("Unexpected key type: " + struct.pemType);
					}
					pubkeyHolder.caption.setText(String.format("%s unknown-bit", type));
				} catch (IOException e) {
					Log.e(TAG, "Error decoding IMPORTED public key at " + pubkey.getId(), e);
				}
			} else {
				try {
					pubkeyHolder.caption.setText(pubkey.getDescription(getApplicationContext()));
				} catch (Exception e) {
					Log.e(TAG, "Error decoding public key at " + pubkey.getId(), e);
					pubkeyHolder.caption.setText(R.string.pubkey_unknown_format);
				}
			}

			if (bound == null) {
				pubkeyHolder.icon.setVisibility(View.GONE);
			} else {
				pubkeyHolder.icon.setVisibility(View.VISIBLE);

				if (bound.isKeyLoaded(pubkey.getNickname()))
					pubkeyHolder.icon.setImageState(new int[] {android.R.attr.state_checked}, true);
				else
					pubkeyHolder.icon.setImageState(new int[] {}, true);
			}
		}

		@Override
		public int getItemCount() {
			return pubkeys.size();
		}

		@Override
		public long getItemId(int position) {
			return pubkeys.get(position).getId();
		}
	}
}
