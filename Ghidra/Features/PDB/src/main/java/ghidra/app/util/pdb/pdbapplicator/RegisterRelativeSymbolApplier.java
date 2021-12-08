/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.pdb.pdbapplicator;

import java.util.Objects;
import java.util.Stack;
import java.util.TreeMap;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractRegisterRelativeAddressMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;

/**
 * Applier for {@link AbstractRegisterRelativeAddressMsSymbol} symbols.
 */
public class RegisterRelativeSymbolApplier extends MsSymbolApplier {

	private AbstractRegisterRelativeAddressMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link PdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public RegisterRelativeSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof AbstractRegisterRelativeAddressMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (AbstractRegisterRelativeAddressMsSymbol) abstractSymbol;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		pdbLogAndInfoMessage(this,
			"Cannot apply " + this.getClass().getSimpleName() + " directly to program");
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) throws PdbException, CancelledException {
		if (!applicator.getPdbApplicatorOptions().applyFunctionVariables()) {
			return;
		}
		if (applyToApplier instanceof FunctionSymbolApplier) {
			FunctionSymbolApplier functionSymbolApplier = (FunctionSymbolApplier) applyToApplier;
			createFunctionVariable(functionSymbolApplier);
		}
	}

	private boolean createFunctionVariable(FunctionSymbolApplier applier) {
		Objects.requireNonNull(applier, "FunctionSymbolApplier cannot be null");
		Function function = applier.getFunction();

		if (function == null) {
			applicator.appendLogMsg("Could not create stack variable for non-existent function.");
			return false;
		}
		Variable[] allVariables = function.getAllVariables();
		TreeMap<Long,RegisterRelativeSymbolApplier> varAppliersByOffset = new TreeMap<Long,RegisterRelativeSymbolApplier>();
		for (MsSymbolApplier varApplier : applier.allAppliers) {
			if (varApplier instanceof RegisterRelativeSymbolApplier){
				varAppliersByOffset.put(((RegisterRelativeSymbolApplier)varApplier).symbol.getOffset(), (RegisterRelativeSymbolApplier)varApplier);
			}
		}
		Stack<RegisterRelativeSymbolApplier> paramAppliers = new Stack<RegisterRelativeSymbolApplier>();
		for(int i =0; i < function.getParameterCount();i++) {
			if (!varAppliersByOffset.isEmpty()) {
				paramAppliers.push(varAppliersByOffset.pollLastEntry().getValue());
			}
		}
		if(function.getParameterCount()  != paramAppliers.size()) {
			function.getAllVariables();
		}
		for(Variable variable: allVariables) {
			try {
				if (variable instanceof AutoParameterImpl  && !paramAppliers.empty()) {
					if(variable.getName().compareTo("__return_storage_ptr__") == 0) {
						continue;
					}
					paramAppliers.pop();
				}
				else if (variable instanceof Parameter && !paramAppliers.empty()) {
					variable.setName(paramAppliers.pop().symbol.getName(),SourceType.IMPORTED);
				}
			}
			catch (DuplicateNameException e) {
				continue;
			}
			catch (InvalidInputException e) {
			e.printStackTrace();
			}
		}	
		return true;
	}
}
