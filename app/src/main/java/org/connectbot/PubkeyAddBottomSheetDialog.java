package org.connectbot;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Spinner;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import de.cotech.hw.openpgp.OpenPgpSecurityKey;

public class PubkeyAddBottomSheetDialog extends BottomSheetDialogFragment
        implements View.OnClickListener {
    public static final String TAG = "PubkeyAddBottomSheetDialog";
    private PubkeyAddBottomSheetListener listener;
    Spinner spinner;

    public static PubkeyAddBottomSheetDialog newInstance() {
        return new PubkeyAddBottomSheetDialog();
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dia_pubkey_add, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        view.findViewById(R.id.bottomsheet_generate_key).setOnClickListener(this);
        view.findViewById(R.id.bottomsheet_import_existing_key).setOnClickListener(this);
        view.findViewById(R.id.bottomsheet_add_openpgp_security_key).setOnClickListener(this);
        view.findViewById(R.id.bottomsheet_setup_openpgp_security_key)
                .setOnClickListener(this);

        spinner = view.findViewById(R.id.bottomsheet_setup_openpgp_security_key_spinner);

        ArrayAdapter adapter = ArrayAdapter.createFromResource(getContext(), R.array.securitykey_setup_spinner, R.layout.dia_pubkey_add_spinner);
        spinner.setAdapter(adapter);
    }

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        if (context instanceof PubkeyAddBottomSheetListener) {
            listener = (PubkeyAddBottomSheetListener) context;
        } else {
            throw new RuntimeException(context.toString() + " must implement listener");
        }
    }

    @Override
    public void onDetach() {
        super.onDetach();
        listener = null;
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.bottomsheet_generate_key:
                listener.onBottomSheetAddKey();
                break;
            case R.id.bottomsheet_import_existing_key:
                listener.onBottomSheetImportKey();
                break;
            case R.id.bottomsheet_add_openpgp_security_key:
                listener.onBottomSheetAddSecurityKey();
                break;
            case R.id.bottomsheet_setup_openpgp_security_key:
                OpenPgpSecurityKey.AlgorithmConfig algorithmConfig;
                switch (spinner.getSelectedItemPosition()) {
                    case 0:
                        algorithmConfig = OpenPgpSecurityKey.AlgorithmConfig.CURVE25519_GENERATE_ON_HARDWARE;
                        break;
                    case 1:
                        algorithmConfig = OpenPgpSecurityKey.AlgorithmConfig.NIST_P256_GENERATE_ON_HARDWARE;
                        break;
                    case 2:
                        algorithmConfig = OpenPgpSecurityKey.AlgorithmConfig.NIST_P384_GENERATE_ON_HARDWARE;
                        break;
                    case 3:
                        algorithmConfig = OpenPgpSecurityKey.AlgorithmConfig.NIST_P521_GENERATE_ON_HARDWARE;
                        break;
                    case 4:
                        algorithmConfig = OpenPgpSecurityKey.AlgorithmConfig.RSA_2048_UPLOAD;
                        break;
                    default:
                        throw new IllegalStateException("Unexpected value: " + spinner.getSelectedItemPosition());
                }

                listener.onBottomSheetSetupSecurityKey(algorithmConfig);
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + view.getId());
        }


        dismiss();
    }

    public interface PubkeyAddBottomSheetListener {
        void onBottomSheetAddKey();

        void onBottomSheetImportKey();

        void onBottomSheetAddSecurityKey();

        void onBottomSheetSetupSecurityKey(OpenPgpSecurityKey.AlgorithmConfig algorithmConfig);
    }
}
