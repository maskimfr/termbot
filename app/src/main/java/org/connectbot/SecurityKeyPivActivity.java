/*
 * ConnectBot: simple, powerful, open-source SSH client for Android
 * Copyright 2019 Dominik Schürmann <dominik@cotech.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.connectbot;

import java.io.IOException;

import org.connectbot.service.SecurityKeyService;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.piv.PivKeyReference;
import de.cotech.hw.piv.PivSecurityKey;
import de.cotech.hw.piv.PivSecurityKeyDialogFragment;
import de.cotech.hw.secrets.PinProvider;
import de.cotech.hw.ui.SecurityKeyDialogFragment;
import de.cotech.hw.ui.SecurityKeyDialogInterface;
import de.cotech.hw.ui.SecurityKeyDialogOptions;

public class SecurityKeyPivActivity extends AppCompatActivity implements SecurityKeyDialogFragment.SecurityKeyDialogCallback<PivSecurityKey> {
	private static final String TAG = "CB.SKPivActivity";

	public static final String EXTRA_PUBKEY_NICKNAME = "pubkey_nickname";

	private SecurityKeyService mSecurityKeyService = null;

	private ServiceConnection mSecurityKeyServiceConnection = new ServiceConnection() {
		@Override
		public void onServiceConnected(ComponentName className, IBinder service) {
			mSecurityKeyService = ((SecurityKeyService.SecurityKeyServiceBinder) service).getService();
		}

		@Override
		public void onServiceDisconnected(ComponentName className) {
			mSecurityKeyService = null;
		}
	};

	@Override
	public void onCreate(Bundle icicle) {
		super.onCreate(icicle);

		String pubkeyNickname = getIntent().getStringExtra(EXTRA_PUBKEY_NICKNAME);
		String title = getString(R.string.security_key_piv_authenticate, pubkeyNickname);

		getApplicationContext().bindService(
				new Intent(getApplicationContext(), SecurityKeyService.class),
				mSecurityKeyServiceConnection,
				Context.BIND_AUTO_CREATE);

		SecurityKeyDialogOptions options = SecurityKeyDialogOptions.builder()
				.setTitle(title)
				.setShowReset(true)
				.setAllowKeyboard(true)
				.setShowSdkLogo(true)
				.setPreventScreenshots(!BuildConfig.DEBUG)
				.setTheme(R.style.SecurityKeyDialog)
				.build();

		SecurityKeyDialogFragment<PivSecurityKey> securityKeyDialogFragment = PivSecurityKeyDialogFragment.newInstance(options);
		securityKeyDialogFragment.show(getSupportFragmentManager());
	}

	@Override
	public void onSecurityKeyDialogDiscovered(@NonNull SecurityKeyDialogInterface dialogInterface,
			@NonNull PivSecurityKey PivSecurityKey, @Nullable PinProvider pinProvider) throws IOException {
		SecurityKeyAuthenticator securityKeyAuthenticator = PivSecurityKey.createSecurityKeyAuthenticator(pinProvider, PivKeyReference.AUTHENTICATION);
		mSecurityKeyService.setAuthenticator(dialogInterface, securityKeyAuthenticator);
	}

	@Override
	public void onSecurityKeyDialogCancel() {
		mSecurityKeyService.cancel();
	}

	@Override
	public void onSecurityKeyDialogDismiss() {
		finish();
	}
}
